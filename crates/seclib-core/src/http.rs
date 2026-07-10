use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SSRFError {
    #[error("URL inválida: {0}")]
    InvalidUrl(String),
    #[error("Esquema no soportado: {0}")]
    ForbiddenScheme(String),
    #[error("URL sin host")]
    MissingHost,
    #[error("IP no segura bloqueada: {0}")]
    UnsafeIp(String),
    #[error("Fallo de resolución DNS: {0}")]
    ResolveFailed(String),
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("SSRF Error: {0}")]
    Ssrf(#[from] SSRFError),
    #[error("Circuit Breaker está abierto y bloqueando peticiones")]
    CircuitBreakerOpen,
    #[error("Error de reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Error de redirección: {0}")]
    Redirect(String),
    #[error("Reintentos agotados sin respuesta")]
    RetriesExhausted,
    #[error("Egress bloqueado por allowlist: {0}")]
    EgressBlocked(String),
}

pub fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_safe_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            // Desenvolver IPv6 mapeado/compatible a IPv4 (p.ej. ::ffff:169.254.169.254) y
            // re-evaluar como v4 para evitar bypass de SSRF (R-5).
            if let Some(v4) = ipv6.to_ipv4_mapped().or_else(|| ipv6.to_ipv4()) {
                return is_safe_ipv4(v4);
            }
            !ipv6.is_loopback()
                && !ipv6.is_unspecified()
                && !ipv6.is_multicast()
                && (ipv6.segments()[0] & 0xfe00) != 0xfc00 // ULA fc00::/7
                && (ipv6.segments()[0] & 0xffc0) != 0xfe80 // Link-local fe80::/10
        }
    }
}

fn is_safe_ipv4(ipv4: std::net::Ipv4Addr) -> bool {
    !ipv4.is_loopback()
        && !ipv4.is_private()
        && !ipv4.is_link_local()
        && !ipv4.is_multicast()
        && !ipv4.is_unspecified()
        && !ipv4.is_documentation()
        && !ipv4.is_broadcast()
        && !is_ipv4_reserved(ipv4)
}

fn is_ipv4_reserved(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    // 0.0.0.0/8 (this-network)
    o[0] == 0
        // 100.64.0.0/10 (CGNAT / shared address space)
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 192.0.0.0/24 (asignaciones de protocolo IETF, incl. metadata en algunas nubes)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 (benchmarking)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // 240.0.0.0/4 (reservado / uso futuro), incl. 255.255.255.255
        || o[0] >= 240
}

pub fn resolve_and_verify_ssrf(url_str: &str) -> Result<IpAddr, SSRFError> {
    resolve_and_verify_ssrf_ext(url_str, false)
}

pub fn resolve_and_verify_ssrf_ext(
    url_str: &str,
    allow_loopback: bool,
) -> Result<IpAddr, SSRFError> {
    let url = Url::parse(url_str).map_err(|e| SSRFError::InvalidUrl(e.to_string()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(SSRFError::ForbiddenScheme(url.scheme().to_string()));
    }
    let host = url.host_str().ok_or(SSRFError::MissingHost)?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if (!allow_loopback || !ip.is_loopback()) && !is_safe_ip(ip) {
            return Err(SSRFError::UnsafeIp(ip.to_string()));
        }
        return Ok(ip);
    }

    let addrs = format!("{host}:80")
        .to_socket_addrs()
        .map_err(|e| SSRFError::ResolveFailed(format!("Fallo al resolver {host}: {e}")))?;

    let mut safe_ip = None;
    for addr in addrs {
        let ip = addr.ip();
        if (!allow_loopback || !ip.is_loopback()) && !is_safe_ip(ip) {
            return Err(SSRFError::UnsafeIp(ip.to_string()));
        }
        if safe_ip.is_none() {
            safe_ip = Some(ip);
        }
    }

    safe_ip.ok_or_else(|| {
        SSRFError::ResolveFailed(format!("No se encontraron IPs seguras para {host}"))
    })
}

/// Tope de entradas y TTL de inactividad de las cachés internas del cliente.
///
/// Antes se usaba `HashMap::clear()` al llegar a 1000 entradas, lo que borraba
/// todo el estado de una vez: incluidos breakers abiertos que protegían hosts en
/// fallo (permitiendo re-inundarlos con solo generar 1000 hosts distintos) y pines
/// de IP ya verificados. `BoundedCache` acota la memoria sin descartar el estado
/// vivo: purga primero lo expirado por TTL y, si sigue lleno, solo la entrada LRU.
const BREAKER_CACHE_MAX_ENTRIES: usize = 1024;
const BREAKER_CACHE_TTL: Duration = Duration::from_secs(3600);
const PIN_CACHE_MAX_ENTRIES: usize = 1024;
const PIN_CACHE_TTL: Duration = Duration::from_secs(300);

struct CacheEntry<V> {
    value: V,
    last_access: Instant,
}

/// Caché en memoria acotada con expiración por TTL de inactividad y desalojo LRU
/// (least-recently-used).
///
/// El tiempo se inyecta como parámetro (`now: Instant`) en cada operación para que
/// las pruebas puedan simular su paso de forma determinista. El desalojo escanea el
/// mapa en O(n), pero `n` está acotado por `max_entries`, así que solo ocurre —y de
/// forma acotada— cuando la caché está llena.
struct BoundedCache<K, V> {
    map: HashMap<K, CacheEntry<V>>,
    max_entries: usize,
    ttl: Duration,
}

impl<K, V> BoundedCache<K, V>
where
    K: Eq + std::hash::Hash + Clone,
{
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::new(),
            // Al menos 1 para mantener la invariante `len <= max_entries` sin que un
            // tope de 0 deje la caché inservible.
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    /// Devuelve el valor vigente (refrescando su acceso para el orden LRU) o `None`
    /// si no existe o expiró; las entradas expiradas se eliminan de forma perezosa.
    fn get(&mut self, key: &K, now: Instant) -> Option<&V> {
        let expired = match self.map.get(key) {
            Some(entry) => now.duration_since(entry.last_access) > self.ttl,
            None => return None,
        };
        if expired {
            self.map.remove(key);
            return None;
        }
        let entry = self.map.get_mut(key)?;
        entry.last_access = now;
        Some(&entry.value)
    }

    /// Inserta o reemplaza una entrada respetando el tope; si la clave es nueva,
    /// primero garantiza hueco (purga TTL + desalojo LRU).
    fn insert(&mut self, key: K, value: V, now: Instant) {
        // La inserción es incondicional; el guard solo decide si hace falta hueco
        // (reemplazar una clave existente no hace crecer el mapa).
        let is_new = !self.map.contains_key(&key);
        if is_new {
            self.make_room(now);
        }
        self.map.insert(
            key,
            CacheEntry {
                value,
                last_access: now,
            },
        );
    }

    /// Obtiene el valor vigente (refrescando su acceso) o lo crea con `factory`,
    /// respetando el tope. Recrea la entrada si había expirado por TTL.
    fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, now: Instant, factory: F) -> &V {
        let expired = matches!(self.map.get(&key), Some(entry) if now.duration_since(entry.last_access) > self.ttl);
        if expired {
            self.map.remove(&key);
        }
        if !self.map.contains_key(&key) {
            self.make_room(now);
        }
        let entry = self.map.entry(key).or_insert_with(|| CacheEntry {
            value: factory(),
            last_access: now,
        });
        entry.last_access = now;
        &entry.value
    }

    /// Garantiza espacio para una entrada nueva sin exceder `max_entries`: primero
    /// purga las expiradas por TTL y, si sigue llena, desaloja la entrada usada hace
    /// más tiempo (LRU). Nunca vacía la caché entera.
    fn make_room(&mut self, now: Instant) {
        if self.map.len() < self.max_entries {
            return;
        }
        let ttl = self.ttl;
        self.map
            .retain(|_, entry| now.duration_since(entry.last_access) <= ttl);
        while self.map.len() >= self.max_entries {
            let lru_key = self
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.last_access)
                .map(|(key, _)| key.clone());
            match lru_key {
                Some(key) => {
                    self.map.remove(&key);
                }
                None => break,
            }
        }
    }
}

struct PinnedResolver {
    pinned_ips: Arc<Mutex<BoundedCache<String, IpAddr>>>,
    allow_loopback: bool,
}

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let pinned = self.pinned_ips.clone();
        let allow_loopback = self.allow_loopback;

        Box::pin(async move {
            let res: Result<Box<dyn Iterator<Item = SocketAddr> + Send>, std::io::Error> =
                async move {
                    let ip_opt = {
                        let mut map = pinned.lock().unwrap_or_else(|e| e.into_inner());
                        map.get(&host, Instant::now()).copied()
                    };

                    if let Some(ip) = ip_opt {
                        let socket_addr = SocketAddr::new(ip, 0);
                        let iter: Box<dyn Iterator<Item = SocketAddr> + Send> =
                            Box::new(std::iter::once(socket_addr));
                        Ok(iter)
                    } else {
                        let addrs = format!("{host}:0").to_socket_addrs()?;
                        let mut resolved = Vec::new();
                        for addr in addrs {
                            let ip = addr.ip();
                            if (!allow_loopback || !ip.is_loopback()) && !is_safe_ip(ip) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    format!("IP bloqueada por SSRF: {ip}"),
                                ));
                            }
                            resolved.push(addr);
                        }
                        if resolved.is_empty() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "Host no encontrado",
                            ));
                        }
                        let iter: Box<dyn Iterator<Item = SocketAddr> + Send> =
                            Box::new(resolved.into_iter());
                        Ok(iter)
                    }
                }
                .await;

            res.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BreakerState {
    Closed { failure_count: u32 },
    Open { opened_at: Instant },
    HalfOpen,
}

pub struct AsyncCircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    state: Mutex<BreakerState>,
}

impl AsyncCircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            state: Mutex::new(BreakerState::Closed { failure_count: 0 }),
        }
    }

    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T, HttpError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, HttpError>>,
    {
        let now = Instant::now();
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let BreakerState::Open { opened_at } = *state {
                if now.duration_since(opened_at) > self.recovery_timeout {
                    *state = BreakerState::HalfOpen;
                } else {
                    return Err(HttpError::CircuitBreakerOpen);
                }
            }
        }

        match f().await {
            Ok(val) => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if *state == BreakerState::HalfOpen {
                    *state = BreakerState::Closed { failure_count: 0 };
                }
                Ok(val)
            }
            Err(e) => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let should_trip = match e {
                    HttpError::Reqwest(ref err) => {
                        // 4xx status does NOT trip the breaker, but network and 5xx do
                        if let Some(status) = err.status() {
                            status.is_server_error()
                        } else {
                            true // network error
                        }
                    }
                    _ => true,
                };

                if should_trip {
                    let next_state = match *state {
                        BreakerState::Closed { failure_count } => {
                            let new_count = failure_count + 1;
                            if new_count >= self.failure_threshold {
                                BreakerState::Open {
                                    opened_at: Instant::now(),
                                }
                            } else {
                                BreakerState::Closed {
                                    failure_count: new_count,
                                }
                            }
                        }
                        BreakerState::HalfOpen | BreakerState::Open { .. } => BreakerState::Open {
                            opened_at: Instant::now(),
                        },
                    };
                    *state = next_state;
                }
                Err(e)
            }
        }
    }
}

pub struct SecureClient {
    client: reqwest::Client,
    pinned_ips: Arc<Mutex<BoundedCache<String, IpAddr>>>,
    breakers: Arc<Mutex<BoundedCache<String, Arc<AsyncCircuitBreaker>>>>,
    allow_loopback: bool,
    egress_allowlist: Option<std::collections::HashSet<String>>,
}

impl SecureClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::new_with_loopback(false)
    }

    #[cfg(feature = "test-loopback")]
    pub fn new_allowing_loopback() -> Result<Self, reqwest::Error> {
        Self::new_with_loopback(true)
    }

    pub fn with_allowlist(mut self, allowlist: std::collections::HashSet<String>) -> Self {
        self.egress_allowlist = Some(allowlist);
        self
    }

    fn new_with_loopback(allow_loopback: bool) -> Result<Self, reqwest::Error> {
        let pinned_ips = Arc::new(Mutex::new(BoundedCache::new(
            PIN_CACHE_MAX_ENTRIES,
            PIN_CACHE_TTL,
        )));
        let resolver = PinnedResolver {
            pinned_ips: pinned_ips.clone(),
            allow_loopback,
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(5))
            .dns_resolver(Arc::new(resolver))
            .redirect(reqwest::redirect::Policy::none()) // We handle redirects manually
            .build()?;

        Ok(Self {
            client,
            pinned_ips,
            breakers: Arc::new(Mutex::new(BoundedCache::new(
                BREAKER_CACHE_MAX_ENTRIES,
                BREAKER_CACHE_TTL,
            ))),
            allow_loopback,
            egress_allowlist: None,
        })
    }

    fn get_breaker(&self, domain: &str) -> Arc<AsyncCircuitBreaker> {
        let mut cache = self.breakers.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .get_or_insert_with(domain.to_string(), Instant::now(), || {
                Arc::new(AsyncCircuitBreaker::new(5, Duration::from_secs(30)))
            })
            .clone()
    }

    pub async fn request(
        &self,
        method: reqwest::Method,
        url_str: &str,
        headers: reqwest::header::HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, HttpError> {
        let url = Url::parse(url_str).map_err(|e| SSRFError::InvalidUrl(e.to_string()))?;
        let domain = url.host_str().unwrap_or("default").to_string();
        let breaker = self.get_breaker(&domain);

        let pinned_ips = self.pinned_ips.clone();
        let client = self.client.clone();
        let initial_url = url_str.to_string();
        let allow_loopback = self.allow_loopback;
        let egress_allowlist = self.egress_allowlist.clone();

        breaker
            .call(move || async move {
                let mut current_url = initial_url;
                let mut redirect_count = 0;
                let max_redirects = 3;

                loop {
                    let parsed = Url::parse(&current_url)
                        .map_err(|e| SSRFError::InvalidUrl(e.to_string()))?;
                    let host = parsed.host_str().ok_or(SSRFError::MissingHost)?;

                    // Pin IP of target url
                    let safe_ip = resolve_and_verify_ssrf_ext(&current_url, allow_loopback)?;
                    {
                        let mut map = pinned_ips.lock().unwrap_or_else(|e| e.into_inner());
                        map.insert(host.to_string(), safe_ip, Instant::now());
                    }

                    // Check egress allowlist
                    if let Some(ref allowlist) = egress_allowlist {
                        if !allowlist.contains(host) {
                            return Err(HttpError::EgressBlocked(host.to_string()));
                        }
                    }

                    // Ejecutar la petición con reintentos/backoff (la IP ya fue validada y pineada arriba)
                    let response = Self::execute_with_retry(
                        &client,
                        &method,
                        &current_url,
                        headers.clone(),
                        body.clone(),
                    )
                    .await?;

                    if response.status().is_redirection() {
                        if redirect_count >= max_redirects {
                            return Err(HttpError::Redirect(
                                "Límite de redirecciones excedido".to_string(),
                            ));
                        }
                        let loc = response
                            .headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|v| v.to_str().ok())
                            .ok_or_else(|| {
                                HttpError::Redirect("Header Location faltante".to_string())
                            })?;

                        let next_url = if Url::parse(loc).is_ok() {
                            loc.to_string()
                        } else {
                            let parsed_base = Url::parse(&current_url)
                                .map_err(|e| SSRFError::InvalidUrl(e.to_string()))?;
                            parsed_base
                                .join(loc)
                                .map_err(|e| SSRFError::InvalidUrl(e.to_string()))?
                                .to_string()
                        };

                        current_url = next_url;
                        redirect_count += 1;
                    } else {
                        return Ok(response);
                    }
                }
            })
            .await
    }

    async fn execute_with_retry(
        client: &reqwest::Client,
        method: &reqwest::Method,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, HttpError> {
        let max_retries = 3;
        let is_idempotent = matches!(
            *method,
            reqwest::Method::GET
                | reqwest::Method::PUT
                | reqwest::Method::DELETE
                | reqwest::Method::HEAD
                | reqwest::Method::OPTIONS
        );
        let has_idempotency_key = headers.keys().any(|k| {
            let ks = k.as_str().to_lowercase();
            ks == "idempotency-key" || ks == "x-idempotency-key"
        });
        let should_retry = is_idempotent || has_idempotency_key;

        for attempt in 1..=max_retries {
            let mut req = client.request(method.clone(), url).headers(headers.clone());
            if let Some(ref bytes) = body {
                req = req.body(bytes.clone());
            }

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_server_error() && attempt < max_retries && should_retry {
                        let base_delay = 2f64.powi(attempt - 1);
                        let jitter =
                            rand::thread_rng().gen_range(-0.25 * base_delay..0.25 * base_delay);
                        let delay = Duration::from_secs_f64((base_delay + jitter).max(0.1));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if attempt < max_retries && should_retry {
                        let base_delay = 2f64.powi(attempt - 1);
                        let jitter =
                            rand::thread_rng().gen_range(-0.25 * base_delay..0.25 * base_delay);
                        let delay = Duration::from_secs_f64((base_delay + jitter).max(0.1));
                        tokio::time::sleep(delay).await;
                    } else {
                        return Err(HttpError::Reqwest(e));
                    }
                }
            }
        }
        Err(HttpError::RetriesExhausted)
    }
}

pub fn verify_webhook_signature(
    body: &[u8],
    secret: &str,
    signature: &str,
    timestamp: &str,
    tolerance_seconds: u64,
) -> bool {
    let ts = match timestamp.parse::<i64>() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = Utc::now().timestamp();
    if (now - ts).unsigned_abs() > tolerance_seconds {
        return false;
    }

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    expected.ct_eq(&sig_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::{AsyncCircuitBreaker, BoundedCache};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn evicts_lru_entry_not_the_whole_cache() {
        // Regresión del fix v2.0.5: al llenarse, la caché desaloja SOLO la entrada
        // usada hace más tiempo, no borra todo (como hacía `clear()` en v2.0.4).
        let mut cache: BoundedCache<String, u32> = BoundedCache::new(3, Duration::from_secs(3600));
        let t = Instant::now();
        cache.insert("a".to_string(), 1, t);
        cache.insert("b".to_string(), 2, t + Duration::from_secs(1));
        cache.insert("c".to_string(), 3, t + Duration::from_secs(2));
        // Refresca "a": ahora la menos usada recientemente es "b".
        assert_eq!(
            cache
                .get(&"a".to_string(), t + Duration::from_secs(3))
                .copied(),
            Some(1)
        );
        // Insertar "d" excede el tope: desaloja "b" y conserva el resto.
        cache.insert("d".to_string(), 4, t + Duration::from_secs(4));
        let now = t + Duration::from_secs(5);
        assert_eq!(cache.map.len(), 3, "la caché nunca debe exceder el tope");
        assert!(
            cache.get(&"b".to_string(), now).is_none(),
            "la LRU 'b' debió salir"
        );
        assert_eq!(cache.get(&"a".to_string(), now).copied(), Some(1));
        assert_eq!(cache.get(&"c".to_string(), now).copied(), Some(3));
        assert_eq!(cache.get(&"d".to_string(), now).copied(), Some(4));
    }

    #[test]
    fn expires_entries_after_ttl_of_inactivity() {
        let ttl = Duration::from_secs(60);
        let mut cache: BoundedCache<String, u32> = BoundedCache::new(8, ttl);
        let t = Instant::now();
        cache.insert("k".to_string(), 7, t);
        // Dentro del TTL: visible (y refresca el acceso a t+30).
        assert_eq!(
            cache
                .get(&"k".to_string(), t + Duration::from_secs(30))
                .copied(),
            Some(7)
        );
        // Pasado el TTL desde el último acceso (t+30): expira y se elimina.
        let after = t + Duration::from_secs(30) + ttl + Duration::from_secs(1);
        assert!(cache.get(&"k".to_string(), after).is_none());
        assert_eq!(
            cache.map.len(),
            0,
            "la entrada expirada se purga de forma perezosa"
        );
    }

    #[test]
    fn never_exceeds_capacity_under_many_distinct_keys() {
        // Simula el caso que en v2.0.4 disparaba `clear()`: muchos hosts distintos.
        let max = 64;
        let mut cache: BoundedCache<String, u32> =
            BoundedCache::new(max, Duration::from_secs(3600));
        let t = Instant::now();
        for i in 0..(max as u64 * 4) {
            cache.insert(format!("host-{i}"), i as u32, t + Duration::from_secs(i));
        }
        assert_eq!(
            cache.map.len(),
            max,
            "el tamaño se mantiene acotado al tope"
        );
        // La entrada más reciente sigue presente; una de las antiguas ya no.
        let last = max as u64 * 4 - 1;
        let now = t + Duration::from_secs(last + 1);
        assert!(cache.get(&format!("host-{last}"), now).is_some());
        assert!(cache.get(&"host-0".to_string(), now).is_none());
    }

    #[test]
    fn get_or_insert_with_reuses_and_refreshes() {
        let mut cache: BoundedCache<String, Arc<AsyncCircuitBreaker>> =
            BoundedCache::new(4, Duration::from_secs(3600));
        let t = Instant::now();
        let first = cache
            .get_or_insert_with("h".to_string(), t, || {
                Arc::new(AsyncCircuitBreaker::new(5, Duration::from_secs(30)))
            })
            .clone();
        // Segunda llamada dentro del TTL: reutiliza la MISMA instancia.
        let second = cache
            .get_or_insert_with("h".to_string(), t + Duration::from_secs(10), || {
                Arc::new(AsyncCircuitBreaker::new(5, Duration::from_secs(30)))
            })
            .clone();
        assert!(
            Arc::ptr_eq(&first, &second),
            "debe reutilizar el breaker existente (no perder su estado)"
        );
        assert_eq!(cache.map.len(), 1);
    }

    #[test]
    fn get_or_insert_with_recreates_after_ttl() {
        let ttl = Duration::from_secs(60);
        let mut cache: BoundedCache<String, Arc<AsyncCircuitBreaker>> = BoundedCache::new(4, ttl);
        let t = Instant::now();
        let first = cache
            .get_or_insert_with("h".to_string(), t, || {
                Arc::new(AsyncCircuitBreaker::new(5, Duration::from_secs(30)))
            })
            .clone();
        // Tras el TTL de inactividad, la entrada caducó: se crea una instancia nueva.
        let later = t + ttl + Duration::from_secs(1);
        let second = cache
            .get_or_insert_with("h".to_string(), later, || {
                Arc::new(AsyncCircuitBreaker::new(5, Duration::from_secs(30)))
            })
            .clone();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "tras el TTL debe recrear el breaker"
        );
        assert_eq!(cache.map.len(), 1);
    }
}
