use bcrypt::{hash, DEFAULT_COST};
use mongodb::{
    bson::{doc, Document},
    Database,
};
use serde::Deserialize;
use warp::http::StatusCode;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

pub async fn register_user(
    req: RegisterRequest,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Перевіряємо, чи користувач уже існує
    if let Ok(Some(_)) = users.find_one(doc! {"username": &req.username}, None).await {
        return Ok(warp::reply::with_status(
            "Користувач уже існує",
            StatusCode::BAD_REQUEST,
        ));
    }

    // Хешуємо пароль
    let hashed_password = hash(req.password, DEFAULT_COST).unwrap();

    // Зберігаємо нового користувача
    let new_user = doc! {
        "username": req.username,
        "password": hashed_password,
    };

    if let Err(e) = users.insert_one(new_user, None).await {
        eprintln!("Помилка збереження користувача: {}", e);
        return Ok(warp::reply::with_status(
            "Не вдалося зареєструвати користувача",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    Ok(warp::reply::with_status(
        "Користувач зареєстрований",
        StatusCode::CREATED,
    ))
}
