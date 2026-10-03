require('dotenv').config();
const { pool } = require('./database');

async function createSchema() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(30) NOT NULL
          CHECK (role IN ('admin','patient','doctor','pharmacy','reception')),
        phone VARCHAR(30),
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS patients (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
        patient_code VARCHAR(30) UNIQUE,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(30),
        gender VARCHAR(30),
        date_of_birth DATE,
        blood_group VARCHAR(10),
        address TEXT,
        emergency_contact VARCHAR(120),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS doctors (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
        doctor_code VARCHAR(30) UNIQUE,
        name VARCHAR(120) NOT NULL,
        specialization VARCHAR(120),
        phone VARCHAR(30),
        email VARCHAR(255),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS appointments (
        id BIGSERIAL PRIMARY KEY,
        patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
        appointment_date DATE NOT NULL,
        appointment_time TIME,
        reason TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending'
          CHECK (status IN (
            'pending',
            'confirmed',
            'completed',
            'cancelled'
          )),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS medical_records (
        id BIGSERIAL PRIMARY KEY,
        patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
        appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
        diagnosis TEXT,
        symptoms TEXT,
        treatment TEXT,
        notes TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS medicines (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(160) NOT NULL,
        generic_name VARCHAR(160),
        batch_number VARCHAR(100),
        quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
        unit_price NUMERIC(12,2) NOT NULL DEFAULT 0,
        expiry_date DATE,
        supplier VARCHAR(160),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS prescriptions (
        id BIGSERIAL PRIMARY KEY,
        patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id BIGINT REFERENCES doctors(id) ON DELETE SET NULL,
        appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
        notes TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'active'
          CHECK (status IN ('active','dispensed','cancelled')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS prescription_items (
        id BIGSERIAL PRIMARY KEY,
        prescription_id BIGINT NOT NULL
          REFERENCES prescriptions(id) ON DELETE CASCADE,
        medicine_id BIGINT REFERENCES medicines(id) ON DELETE SET NULL,
        medicine_name VARCHAR(160) NOT NULL,
        dosage VARCHAR(100),
        frequency VARCHAR(100),
        duration VARCHAR(100),
        instructions TEXT
      );

      CREATE TABLE IF NOT EXISTS dispensations (
        id BIGSERIAL PRIMARY KEY,
        prescription_id BIGINT REFERENCES prescriptions(id) ON DELETE SET NULL,
        patient_id BIGINT REFERENCES patients(id) ON DELETE SET NULL,
        pharmacist_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
        total_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
        dispensed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS bills (
        id BIGSERIAL PRIMARY KEY,
        patient_id BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
        appointment_id BIGINT REFERENCES appointments(id) ON DELETE SET NULL,
        amount NUMERIC(12,2) NOT NULL DEFAULT 0,
        payment_method VARCHAR(30),
        payment_status VARCHAR(30) NOT NULL DEFAULT 'pending'
          CHECK (payment_status IN ('pending','paid','cancelled')),
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        paid_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(160) NOT NULL,
        entity_type VARCHAR(80),
        entity_id BIGINT,
        details JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_users_email
        ON users(email);

      CREATE INDEX IF NOT EXISTS idx_appointments_patient
        ON appointments(patient_id);

      CREATE INDEX IF NOT EXISTS idx_appointments_doctor
        ON appointments(doctor_id);

      CREATE INDEX IF NOT EXISTS idx_prescriptions_patient
        ON prescriptions(patient_id);

      CREATE INDEX IF NOT EXISTS idx_medical_records_patient
        ON medical_records(patient_id);

      CREATE INDEX IF NOT EXISTS idx_bills_patient
        ON bills(patient_id);
    `);

    await client.query('COMMIT');

    console.log('HOSPITAL DATABASE SCHEMA CREATED SUCCESSFULLY');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('SCHEMA CREATION FAILED');
    console.error(error);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

createSchema();