create database hr_portal;
use hr_portal;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    azure_oid VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    role ENUM('hr', 'interviewer', 'manager', 'admin', 'hr lead') NOT NULL,
    department VARCHAR(100),
    is_external BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE interview_hierarchy (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requisition_id INT,
    level INT, -- 1 to 5
    interviewer_name VARCHAR(255),
    interviewer_email VARCHAR(255),
    FOREIGN KEY (requisition_id) REFERENCES requisitions(id)
);

CREATE TABLE requisitions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_title VARCHAR(255),
    department VARCHAR(255),
    number_of_openings INT,
    skills_required TEXT,
    location VARCHAR(255),
    hiring_type ENUM('Replacement', 'New'),
    budget DECIMAL(10,2),
    job_description TEXT,
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    assigned_to VARCHAR(255)
);


CREATE TABLE candidates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(15),
    skills text,
    resume BLOB,
    requisition_id INT,
    submitted_by varchar(100),
    shortlisted_by INT,
    shortlisted_on DATETIME,
    is_shortlisted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (requisition_id) REFERENCES requisitions(id),
    FOREIGN KEY (submitted_by) REFERENCES users(email),
    FOREIGN KEY (shortlisted_by) REFERENCES users(id)
);

CREATE TABLE interview_schedule (
    id INT AUTO_INCREMENT PRIMARY KEY,
    candidate_id INT,
    level INT,
    interview_datetime DATETIME,
    interviewer_name VARCHAR(255),
    interviewer_email VARCHAR(255),
    UNIQUE(candidate_id, level),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id)
);
