use warp::Filter;

#[tokio::main]
async fn main() {
    // Для перевірки
    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    // Запус сервера
    warp::serve(hello).run(([127, 0, 0, 1], 3030)).await;
}
