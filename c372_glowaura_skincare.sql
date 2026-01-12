-- WARNING: this DROPS your existing tables
CREATE DATABASE IF NOT EXISTS `c372_glowaura_skincare`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_general_ci;
USE `c372_glowaura_skincare`;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `order_items`;
DROP TABLE IF EXISTS `orders`;
DROP TABLE IF EXISTS `carts`;
DROP TABLE IF EXISTS `products`;
DROP TABLE IF EXISTS `categories`;
DROP TABLE IF EXISTS `users`;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE `users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `address` VARCHAR(255) NOT NULL,
  `contact` VARCHAR(20) NOT NULL,
  `role` VARCHAR(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `categories` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(64) COLLATE utf8mb4_general_ci NOT NULL UNIQUE,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `products` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `productName` VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  `quantity` INT NOT NULL,
  `price` DECIMAL(10,2) NOT NULL,
  `image` VARCHAR(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `category` VARCHAR(64) COLLATE utf8mb4_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `carts` (
  `userId` INT NOT NULL,
  `cartData` TEXT,
  PRIMARY KEY (`userId`),
  CONSTRAINT `fk_carts_user` FOREIGN KEY (`userId`)
    REFERENCES `users`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `orders` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userId` INT NOT NULL,
  `subtotal` DECIMAL(10,2) NOT NULL,
  `deliveryOption` VARCHAR(20) NOT NULL,
  `deliveryCost` DECIMAL(10,2) NOT NULL,
  `total` DECIMAL(10,2) NOT NULL,
  `paymentMethod` VARCHAR(20) NOT NULL,
  `status` VARCHAR(20) NOT NULL,
  `deliveryStatus` VARCHAR(20) NOT NULL,
  `createdAt` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_orders_userId` (`userId`),
  CONSTRAINT `fk_orders_user` FOREIGN KEY (`userId`)
    REFERENCES `users`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `order_items` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `orderId` INT NOT NULL,
  `productId` INT NOT NULL,
  `productName` VARCHAR(255) NOT NULL,
  `price` DECIMAL(10,2) NOT NULL,
  `quantity` INT NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_order_items_orderId` (`orderId`),
  CONSTRAINT `fk_order_items_order` FOREIGN KEY (`orderId`)
    REFERENCES `orders`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- LUXURY SKINCARE CATEGORIES
INSERT INTO `categories` (`name`) VALUES
('Cleansers'),
('Serums'),
('Moisturizers'),
('Sun Care'),
('Eye Care'),
('Masks');

-- LUXURY SKINCARE PRODUCTS
INSERT INTO `products` (`id`,`productName`,`quantity`,`price`,`image`,`category`) VALUES
(1,'Velvet Cloud Cream Cleanser',80,29.00,'cleanser_velvet_cloud.png','Cleansers'),
(2,'Green Tea Gel Cleanser',100,24.00,'cleanser_green_tea.png','Cleansers'),
(3,'Radiance Vitamin C Serum 15%',60,69.00,'serum_vitc_15.png','Serums'),
(4,'Midnight Repair Retinol Serum',45,79.00,'serum_retinol_midnight.png','Serums'),
(5,'HydraSilk Daily Moisturizer',90,58.00,'moist_hydrasilk.png','Moisturizers'),
(6,'Ceramide Barrier Cream Rich',40,72.00,'moist_ceramide_rich.png','Moisturizers'),
(7,'Weightless SPF50 Fluid',120,45.00,'suncare_spf50_fluid.png','Sun Care'),
(8,'Tinted Mineral SPF40',70,52.00,'suncare_tinted_spf40.png','Sun Care'),
(9,'Peptide Eye Renewal Cream',55,68.00,'eye_peptide_renewal.png','Eye Care'),
(10,'24K Gold Illuminating Eye Masks (6 pairs)',35,54.00,'eye_gold_masks.png','Eye Care'),
(11,'Rose Quartz Overnight Sleeping Mask',50,64.00,'mask_rose_quartz.png','Masks'),
(12,'Pore-Refining Clay Detox Mask',65,39.00,'mask_clay_detox.png','Masks');

-- USERS (admin + sample customers)
-- Passwords are SHA1('123456') = 7c4a8d09ca3762af61e59520943dc26494f8941b
INSERT INTO `users` (`id`,`username`,`email`,`password`,`address`,`contact`,`role`) VALUES
(1,'Peter Lim','peter@peter.com','7c4a8d09ca3762af61e59520943dc26494f8941b','17 Glow Avenue, Orchard','98765432','admin'),
(2,'Emily Tan','emily.tan@example.com','7c4a8d09ca3762af61e59520943dc26494f8941b','21 Serangoon Skye Residences','91234567','user'),
(3,'Noah Lee','noah.lee@example.com','7c4a8d09ca3762af61e59520943dc26494f8941b','55 Marina Bay Suites','97654321','user'),
(4,'Chloe Ong','chloe.ong@example.com','7c4a8d09ca3762af61e59520943dc26494f8941b','8 River Valley Lane','96543210','user');
