use crate::handlers::{register_user, RegisterRequest};
use mongodb::Database;
use warp::Filter;

pub fn register_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("register")
        .and(warp::post())
        .and(warp::body::json::<RegisterRequest>())
        .and(with_db(db))
        .and_then(register_user)
}

fn with_db(
    db: Database,
) -> impl Filter<Extract = (Database,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}
