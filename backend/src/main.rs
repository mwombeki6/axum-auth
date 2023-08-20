#[derive(Clone)]
pub struct AppState {
    postgres: PgPool,
    key: Key
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

#[shuttle_runtime::main]
async fn axum(
    #[shuttle_static_folder::StaticFolder] static_folder: PathBuf,
    #[shuttle_shared_db::Postgres] postgres: PgPool,
    #[shuttle_secrets::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    sqlx::migrate!().run(&postgres).await;

    let state = AppState {
        postgres,
        key: Key::generate()
    };

    let router = create_router(static_folder, state);

    Ok(router.into())
}