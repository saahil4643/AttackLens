"""
Sample In-Memory Vulnerable Project Generator for AttackLens SAST Demo & Testing
"""

import io
import zipfile


def build_sample_vulnerable_project_zip() -> io.BytesIO:
    """
    Creates an in-memory ZIP containing multi-language demo source code
    with intentionally modeled static security vulnerabilities.
    """
    mem_zip = io.BytesIO()

    files = {
        "requirements.txt": """django==5.1.0
requests>=2.31.0
psycopg2-binary==2.9.9
pyyaml==6.0.1
""",
        "package.json": """{
  "name": "attacklens-demo-service",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "jsonwebtoken": "^9.0.2",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "mocha": "^10.2.0"
  }
}
""",
        "config/settings.py": """# Django Application Configuration
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Unsafe Debug setting
DEBUG = True

# Hardcoded Secret Key and AWS Credentials
SECRET_KEY = 'super-secret-production-django-key-unmasked'
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# Database URL with embedded credentials
DATABASE_URL = 'postgres://admin:SuperSecretPass123!@db.internal:5432/production_db'
""",
        "backend/views.py": """from django.http import JsonResponse, HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
import os
import subprocess
import requests
import pickle

@csrf_exempt
def user_search(request):
    # Untrusted user input
    user_id = request.GET.get('id', '')
    
    # 1. SQL Injection: Raw query string formatting
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor = connection.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    
    return JsonResponse({"results": results})

def run_diagnostic(request):
    host = request.GET.get('host', '127.0.0.1')
    # 2. Command Injection via subprocess shell=True
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True)
    return HttpResponse(output)

def download_report(request):
    filename = request.GET.get('file', 'report.pdf')
    # 3. Path Traversal
    filepath = os.path.join('/var/reports/', filename)
    with open(filepath, 'rb') as f:
        data = f.read()
    return HttpResponse(data)

def webhook_proxy(request):
    target_url = request.GET.get('url')
    # 4. SSRF
    resp = requests.get(target_url, timeout=5)
    return HttpResponse(resp.text)

def load_user_session(request):
    raw_data = request.body
    # 5. Insecure Deserialization
    session_obj = pickle.loads(raw_data)
    return JsonResponse({"status": "loaded"})
""",
        "server/routes.js": """const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const pool = new Pool();
const JWT_SECRET = 'hardcoded-jwt-super-token-secret-xyz';

router.get('/api/lookup', async (req, res) => {
    const term = req.query.q;
    // SQL Injection in Node
    const query = `SELECT * FROM items WHERE name LIKE '%${term}%'`;
    const result = await pool.query(query);
    res.json(result.rows);
});

router.post('/api/system/backup', (req, res) => {
    const backupName = req.body.name;
    // Command Injection in Node
    exec(`tar -czf ${backupName}.tar.gz /data`, (err, stdout) => {
        res.send(stdout);
    });
});

router.post('/api/login', (req, res) => {
    const user = { id: 1, role: 'admin' };
    const token = jwt.sign(user, JWT_SECRET, { algorithm: 'HS256' });
    res.cookie('auth_token', token, { httpOnly: false });
    res.json({ token });
});

module.exports = router;
""",
        "src/main/java/com/app/UserService.java": """package com.app;

import java.io.*;
import java.sql.*;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    public void processUser(String userInput, Connection conn) throws Exception {
        // Java SQL Injection
        Statement statement = conn.createStatement();
        ResultSet rs = statement.executeQuery("SELECT * FROM accounts WHERE user = '" + userInput + "'");
        
        // Java Command Execution
        Runtime.getRuntime().exec("echo Processing user " + userInput);
    }
    
    public Object deserializeData(byte[] data) throws Exception {
        // Java Insecure Deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
""",
        "api/upload_handler.php": """<?php
$conn = mysqli_connect("localhost", "root", "root", "testdb");

if (isset($_GET['user_id'])) {
    $id = $_GET['user_id'];
    // PHP SQL Injection
    $res = $conn->query("SELECT * FROM users WHERE id = " . $id);
}

if (isset($_POST['cmd'])) {
    // PHP Command Injection
    system($_POST['cmd']);
}

if (isset($_POST['payload'])) {
    // PHP Insecure Deserialization
    $obj = unserialize($_POST['payload']);
}
?>
""",
        "tests/test_views.py": """import unittest

class TestViews(unittest.TestCase):
    def test_sample(self):
        self.assertEqual(1 + 1, 2)
"""
    }

    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            zf.writestr(filename, content.encode("utf-8"))

    mem_zip.seek(0)
    return mem_zip
