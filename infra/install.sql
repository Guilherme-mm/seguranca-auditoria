

USE db;

CREATE TABLE IF NOT EXISTS `db`.`host_tb` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `ip` VARCHAR(45) NOT NULL,
  `domain` VARCHAR(300) NOT NULL,
  `is_eu` TINYINT NULL,
  `continent` VARCHAR(45) NULL,
  `country` VARCHAR(45) NULL,
  `region` VARCHAR(45) NULL,
  `city` VARCHAR(45) NULL,
  `location` POINT NULL,
  `asn` VARCHAR(45) NULL,
  `organisation` VARCHAR(45) NULL,
  `is_tor` TINYINT NULL,
  `is_proxy` TINYINT NULL,
  `is_anonymous` TINYINT NULL,
  `is_known_attacker` TINYINT NULL,
  `is_known_abuser` TINYINT NULL,
  `is_threat` TINYINT NULL,
  `is_bogon` TINYINT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS `db`.`url_tb` (
  `url` VARCHAR(300) NOT NULL,
  `id` INT NOT NULL AUTO_INCREMENT,
  `http_version` VARCHAR(45) NULL,
  `http_code` VARCHAR(45) NULL,
  `alarm_words_count` INT NULL DEFAULT 0,
  `server_type` VARCHAR(100) NULL,
  `host_id` INT NULL,
  PRIMARY KEY (`id`),
  -- UNIQUE INDEX `url_UNIQUE` (`url` ASC),
  INDEX `url_host_fk_idx` (`host_id` ASC),
  CONSTRAINT `url_host_fk`
    FOREIGN KEY (`host_id`)
    REFERENCES `db`.`host_tb` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;