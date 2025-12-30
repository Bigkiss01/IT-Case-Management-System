-- Multi-Location Case Log Management System Schema
-- Version 2.0 - With Authentication & Multi-Location Support

-- ============================================
-- LOCATIONS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS locations (
    code VARCHAR(10) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert 4 locations
INSERT INTO locations (code, name, short_name) VALUES
('hktmb', 'Phuket Marriott Resort & Spa Merlin Beach', 'Merlin Beach'),
('hktcp', 'Courtyard By Marriott Phuket Patong Beach', 'Courtyard Patong'),
('hktml', 'Le Méridien Phuket Beach Resort', 'Le Méridien'),
('hktfp', 'Four Points by Sheraton Phuket Patong Beach Resort', 'Four Points');

-- ============================================
-- USERS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    eid VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    position ENUM('ITM', 'ITS', 'ITO', 'ITO Trainee'),
    phone VARCHAR(20),
    full_name VARCHAR(100),
    role ENUM('user', 'admin', 'superadmin') DEFAULT 'user',
    is_locked BOOLEAN DEFAULT FALSE,
    locked_until DATETIME NULL,
    failed_attempts INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================
-- USER LOCATIONS (Access Control)
-- ============================================
CREATE TABLE IF NOT EXISTS user_locations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    location_code VARCHAR(10) NOT NULL,
    can_view BOOLEAN DEFAULT TRUE,
    can_edit BOOLEAN DEFAULT FALSE,
    can_delete BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (location_code) REFERENCES locations(code) ON DELETE CASCADE,
    UNIQUE KEY unique_user_location (user_id, location_code)
);

-- ============================================
-- OTP TOKENS
-- ============================================
CREATE TABLE IF NOT EXISTS otp_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    purpose ENUM('register', 'reset_password') NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- CASE LOGS - HKTMB (Merlin Beach)
-- ============================================
CREATE TABLE IF NOT EXISTS case_logs_hktmb (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_no VARCHAR(50),
    case_date DATE,
    issues VARCHAR(200),
    description TEXT,
    step_to_resolve TEXT,
    opened_by VARCHAR(100),
    department VARCHAR(100),
    status VARCHAR(50) DEFAULT 'In progress',
    resolved_by VARCHAR(200),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================
-- CASE LOGS - HKTCP (Courtyard Patong)
-- ============================================
CREATE TABLE IF NOT EXISTS case_logs_hktcp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_no VARCHAR(50),
    case_date DATE,
    issues VARCHAR(200),
    description TEXT,
    step_to_resolve TEXT,
    opened_by VARCHAR(100),
    department VARCHAR(100),
    status VARCHAR(50) DEFAULT 'In progress',
    resolved_by VARCHAR(200),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================
-- CASE LOGS - HKTML (Le Méridien)
-- ============================================
CREATE TABLE IF NOT EXISTS case_logs_hktml (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_no VARCHAR(50),
    case_date DATE,
    issues VARCHAR(200),
    description TEXT,
    step_to_resolve TEXT,
    opened_by VARCHAR(100),
    department VARCHAR(100),
    status VARCHAR(50) DEFAULT 'In progress',
    resolved_by VARCHAR(200),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================
-- CASE LOGS - HKTFP (Four Points)
-- ============================================
CREATE TABLE IF NOT EXISTS case_logs_hktfp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_no VARCHAR(50),
    case_date DATE,
    issues VARCHAR(200),
    description TEXT,
    step_to_resolve TEXT,
    opened_by VARCHAR(100),
    department VARCHAR(100),
    status VARCHAR(50) DEFAULT 'In progress',
    resolved_by VARCHAR(200),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================
-- DEFAULT SUPERADMIN USER
-- Password: admin123 (bcrypt hashed - generated in Docker container)
-- ============================================
INSERT INTO users (eid, password_hash, email, full_name, role) VALUES ('admin', '$2b$12$t5oVC4.JAxa41jpBjw6LSOis3gV/sj7.lEVGqR/8W2QgvgXT9icDeRUszy', 'admin@localhost', 'System Administrator', 'superadmin');

-- Grant superadmin access to all locations
INSERT INTO user_locations (user_id, location_code, can_view, can_edit, can_delete) 
SELECT 1, code, TRUE, TRUE, TRUE FROM locations;
