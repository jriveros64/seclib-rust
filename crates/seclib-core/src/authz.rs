use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    UsersRead,
    UsersManage,
    FilesUpload,
    FinanceRead,
    FinanceExport,
    Admin,
}

pub fn get_role_permissions(role: &str) -> HashSet<Permission> {
    let mut perm = HashSet::new();
    match role {
        "viewer" => {
            perm.insert(Permission::UsersRead);
        }
        "analyst" => {
            perm.insert(Permission::UsersRead);
            perm.insert(Permission::FinanceRead);
            perm.insert(Permission::FilesUpload);
        }
        "admin" => {
            perm.insert(Permission::UsersRead);
            perm.insert(Permission::UsersManage);
            perm.insert(Permission::FilesUpload);
            perm.insert(Permission::FinanceRead);
            perm.insert(Permission::FinanceExport);
            perm.insert(Permission::Admin);
        }
        _ => {}
    }
    perm
}

#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("Recurso no encontrado")]
    NotFound,
    #[error("Permiso denegado: {0}")]
    Forbidden(String),
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
}

pub fn check_permission(roles: &[String], required: Permission) -> Result<(), AuthzError> {
    let mut user_permissions = HashSet::new();
    for role in roles {
        user_permissions.extend(get_role_permissions(role));
    }
    if user_permissions.contains(&required) || user_permissions.contains(&Permission::Admin) {
        Ok(())
    } else {
        Err(AuthzError::Forbidden(format!(
            "Permiso requerido {required:?} no asignado en roles {roles:?}"
        )))
    }
}

pub fn verify_tenant(user_tenant_id: &str, resource_tenant_id: &str) -> Result<(), AuthzError> {
    if user_tenant_id != resource_tenant_id {
        return Err(AuthzError::NotFound);
    }
    Ok(())
}

pub async fn set_db_session_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    setting_name: &str,
) -> Result<(), AuthzError> {
    if !setting_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(AuthzError::Forbidden(
            "Invalid RLS setting name".to_string(),
        ));
    }

    sqlx::query("SELECT set_config($1, $2, true)")
        .bind(setting_name)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
