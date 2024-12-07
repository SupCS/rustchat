use crate::handlers::{
    authorize_user, login_user, protected_handler, register_user, CustomError, LoginRequest,
    RegisterRequest,
};
use mongodb::Database;
use warp::{filters::header::header, reject, Filter};

/// Маршрут для реєстрації
pub fn register_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("register")
        .and(warp::post())
        .and(warp::body::json::<RegisterRequest>())
        .and(with_db(db.clone()))
        .and_then(register_user)
}

/// Маршрут для входу
pub fn login_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("login")
        .and(warp::post())
        .and(warp::body::json::<LoginRequest>())
        .and(with_db(db))
        .and_then(login_user)
}

/// Захищений маршрут
pub fn protected_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("protected")
        .and(warp::get())
        .and(with_auth())
        .and(with_db(db))
        .and_then(protected_handler)
}

/// Middleware для перевірки JWT
fn with_auth() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    header::<String>("authorization")
        .map(|header: String| header.trim_start_matches("Bearer ").to_string())
        .and_then(|token: String| async move {
            authorize_user(token)
                .await
                .map_err(|_| reject::custom(CustomError("Неавторизовано".to_string())))
        })
}

/// Middleware для доступу до бази даних
fn with_db(
    db: Database,
) -> impl Filter<Extract = (Database,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}
