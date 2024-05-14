pub mod bulletin;
pub mod callbacks;
/// This module defines types useful in dealing with interactions between the user and service
/// provider. The key type is the `Interaction`, which is a way to package the information of a
/// state change and callbacks in one structure.
pub mod interaction;
/// Defines types that are necessary for any zero knowledge object.
pub mod object;
pub mod service;
/// Structures and traits pertaining to user data and proving statements on user data. Allows
/// a `User` to interact with a service provider.
pub mod user;
