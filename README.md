# Attack Lens 🔍

**Attack Lens** is a modular web security assessment platform designed to automate the analysis of websites and APIs and provide actionable security insights.

The platform brings multiple security assessment capabilities together through a centralized backend, allowing security findings from different scanners to be collected, processed, correlated, and presented in a structured format.

> **Purpose:** Simplify security assessment by bringing multiple checks into a single workflow while keeping individual scanning components modular and maintainable.

---

## 🚀 Key Features

* **Website & API Security Assessment**

  * Analyze application endpoints and APIs for common security issues.
  * Organize security checks into independent scanning components.

* **Modular Scanner Architecture**

  * Individual scanners can perform specialized security checks.
  * New security checks can be added without redesigning the complete platform.

* **Centralized Backend**

  * Django-based backend for managing assessment workflows and results.
  * Provides a central layer for coordinating different scanning components.

* **Security Finding Processing**

  * Collect findings from multiple assessment components.
  * Normalize and process results into a structured format.
  * Correlate related findings to provide more meaningful security insights.

* **Risk Classification**

  * Categorize discovered issues based on their security impact.
  * Generate actionable results for developers and security teams.

* **Configuration & Dependency Analysis**

  * Assess application configurations and dependencies as part of the security workflow.

* **Exposed Secret Detection**

  * Identify potentially exposed credentials and sensitive secrets during assessment.

* **Structured Security Reports**

  * Present discovered issues with useful contextual information to make remediation easier.

---

## 🏗️ Architecture

Attack Lens follows a modular architecture where the central backend coordinates different security assessment components.

```text
                         ┌──────────────────────┐
                         │      User / Client   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    React Frontend    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Django Backend    │
                         │  Assessment Manager  │
                         └──────────┬───────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
          ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
          │   Endpoint   │  │ Configuration│  │  Dependency  │
          │    Scanner   │  │    Scanner   │  │    Scanner   │
          └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                 │                 │                 │
                 └─────────────────┼─────────────────┘
                                   ▼
                         ┌──────────────────────┐
                         │ Finding Processor    │
                         │ & Correlation Layer  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Risk Classification│
                         │    & Reporting       │
                         └──────────────────────┘
```

### Architecture Principles

Attack Lens is designed around three main principles:

**Modularity**
Security checks are separated into independent components so that individual scanners can be developed and improved independently.

**Centralized orchestration**
The Django backend manages assessment workflows and coordinates the collection and processing of scanner results.

**Structured findings**
Different scanner outputs are processed into a consistent representation so they can be correlated and presented as actionable security findings.

---

## 🛠️ Technology Stack

| Layer                | Technology                 |
| -------------------- | -------------------------- |
| Backend              | Django                     |
| Frontend             | React                      |
| Programming Language | Python                     |
| Security Analysis    | Custom scanning components |
| API Communication    | REST APIs                  |
| Version Control      | Git / GitHub               |

---

## 🔎 Assessment Workflow

A typical assessment follows this workflow:

```text
1. Target / Application
          ↓
2. Assessment Initialization
          ↓
3. Security Scanners
          ↓
4. Finding Collection
          ↓
5. Finding Processing
          ↓
6. Finding Correlation
          ↓
7. Risk Classification
          ↓
8. Security Report
```

### Step 1 — Initialize Assessment

The user starts a security assessment through the application.

### Step 2 — Run Security Checks

Attack Lens invokes the appropriate security assessment components based on the selected assessment scope.

### Step 3 — Collect Findings

Each scanner produces structured findings containing relevant information about the detected issue.

### Step 4 — Process Results

The backend processes and normalizes scanner results into a common structure.

### Step 5 — Correlate Findings

Related findings can be grouped and correlated to provide better context instead of presenting isolated results.

### Step 6 — Classify Risk

Findings are categorized according to their potential security impact.

### Step 7 — Generate Results

The final results are presented in a structured format that helps developers understand and prioritize remediation.

---

## 🔐 Security Checks

Attack Lens is designed to assess multiple areas of web application security, including:

### Application Endpoints

Assessment of application routes and API endpoints to identify potentially exposed or insecure functionality.

### API Security

Security analysis of API endpoints and their configurations.

### Exposed Secrets

Detection of potentially exposed credentials, API keys, tokens, and other sensitive values.

### Dependencies

Analysis of application dependencies to identify security-related risks.

### Configuration

Assessment of security-relevant application and deployment configurations.

---

## 📂 Project Structure

A modular structure can be organized as follows:

```text
attack-lens/
│
├── backend/
│   ├── manage.py
│   ├── config/
│   ├── assessments/
│   ├── scanners/
│   │   ├── endpoint/
│   │   ├── api/
│   │   ├── secrets/
│   │   ├── dependencies/
│   │   └── configuration/
│   ├── findings/
│   └── reports/
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── services/
│
├── requirements.txt
├── README.md
└── .gitignore
```

> The exact structure may differ depending on the current implementation.

---

## ⚙️ Installation

### Prerequisites

Make sure the following are installed:

* Python 3.x
* Node.js
* npm
* Git

### Clone the Repository

```bash
git clone https://github.com/<your-username>/attack-lens.git
cd attack-lens
```

### Backend Setup

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

On Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run database migrations:

```bash
python manage.py migrate
```

Start the backend:

```bash
python manage.py runserver
```

### Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend and backend can then be accessed through their respective local development URLs.

---

## 🧪 Example Use Case

A development team wants to perform a security assessment of an application before deployment.

Instead of manually checking different areas of the application, the team can use Attack Lens to initiate an assessment.

```text
Application
    │
    ├── API / Endpoint Analysis
    ├── Secret Detection
    ├── Dependency Analysis
    └── Configuration Analysis
             │
             ▼
      Finding Processing
             │
             ▼
      Risk Classification
             │
             ▼
       Security Results
```

The resulting findings provide developers with a centralized view of potential security issues and areas requiring attention.

---

## 🎯 Project Goals

Attack Lens aims to:

* Automate repetitive security assessment tasks.
* Provide a centralized security assessment workflow.
* Make security findings easier to understand.
* Maintain a modular scanner architecture.
* Reduce the effort required to perform application security checks.
* Help developers identify security issues earlier in the development lifecycle.

---

## 🔮 Future Improvements

Potential future improvements include:

* Additional security scanners.
* Improved false-positive reduction.
* More advanced risk scoring.
* CI/CD pipeline integration.
* Automated security regression testing.
* Historical assessment comparison.
* Improved reporting and visualization.
* Containerized scanner execution.
* Role-based access control.
* Notification and alerting integrations.

---

## ⚠️ Responsible Use

Attack Lens should only be used to assess applications and systems that you own or have explicit authorization to test.

Do not use the platform to scan or test systems without permission.

The project is intended for **authorized security testing, defensive security research, and application security assessment**.

---

## 👨‍💻 Author

**Sahil Bhandare**

B.E. Information Technology
JSPM’s Bhivarabai Institute of Technology and Research

---
