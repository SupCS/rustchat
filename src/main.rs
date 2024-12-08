mod db;
mod handlers;
mod routes;

use dotenvy::dotenv;
use std::error::Error;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    // Підключення до бази даних
    let db = db::connect_to_db().await?;

    // Реєстрація API маршрутів
    let register = routes::register_routes(db.clone());
    let login = routes::login_routes(db.clone());
    let protected = routes::protected_routes(db.clone());
    let messages = routes::message_routes(db.clone());
    let current_user = routes::current_user_route();
    let chats = routes::chats_route(db.clone());
    let logout = routes::logout_routes();

    let api_routes = register
        .or(login)
        .or(protected)
        .or(messages)
        .or(current_user)
        .or(chats)
        .or(logout);

    // Додавання обслуговування статичних файлів
    let frontend = warp::fs::dir("./frontend");

    // Об'єднання маршрутів
    let routes = frontend.or(api_routes);

    // Запуск сервера
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}
