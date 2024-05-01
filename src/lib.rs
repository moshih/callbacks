#![feature(associated_type_defaults)]
pub mod generic;
pub mod impls;
mod util;

pub trait ObjectBulletin<Com> {
    fn verify_creation();

    fn verify_settle();

    fn object_is_member();
}

pub trait CallbackBulletin {
    fn verify_call();

    fn callback_is_member();

    fn callback_is_not_member();
}

pub trait ServiceProvider<SK, VK> {
    fn verify_callback_creation();

    fn call_cb();
}
