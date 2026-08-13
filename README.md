# 🍯 Honeypot for Attack Detection

A small, low-interaction honeypot built for **defensive cybersecurity research and learning**.

The project creates a fake SSH-style service that attracts connection and login attempts, records what happens, and then analyzes the collected activity for suspicious behavior. A web dashboard makes it easy to see what's happening and review detected attacks.

The entire project is designed to run inside an **isolated lab environment**.

> ⚠️ **For educational and authorized lab use only.** Do not expose this honeypot to the public internet or use it on networks you don't own or have permission to test.

## 🔎 What does it do?

The honeypot acts like a simple SSH service, but it isn't a real SSH server. It accepts connections and displays a fake login prompt, while recording the activity for later analysis.

The main features include:

* A fake SSH-style login service that records usernames, passwords, and command attempts.
* Authentication that always fails, so there is no real system access behind the honeypot.
* An optional fake shell that records commands as text without ever executing them.
* A SQLite database for storing connection, authentication, and command activity.
* A rule-based detection system that looks for suspicious patterns such as repeated login failures, username sweeps, rapid connection attempts, and common attacker-tool commands.
* Severity levels ranging from **LOW** to **CRITICAL**, along with an explanation for why an event was flagged.
* A Flask dashboard for viewing activity, alerts, statistics, source IPs, usernames, passwords, and commands.
* A statistics module for analyzing things like attacks over time, activity by IP, and detection rates.
* A safe traffic simulator for testing the honeypot inside your own lab.

For the full technical explanation, architecture, threat model, testing methodology, and design decisions, see the [project documentation](docs/Honeypot_Project_Documentation.md).

## 📁 Project Structure

```text
honeypot-project/
├── honeypot/              # Fake TCP service and configuration
│   ├── service.py         # Main honeypot service
│   ├── banners.py         # Fake login and shell prompts
│   ├── config.py          # Environment-based configuration
│   └── Dockerfile
├── db/                    # Database schema and data access
│   ├── schema.sql
│   └── database.py
├── detection/             # Detection and alerting rules
│   └── rules.py
├── dashboard/              # Flask monitoring dashboard
│   ├── app.py
│   ├── queries.py
│   ├── templates/
│   └── static/
├── testing/                # Safe traffic simulation
│   ├── simulate_traffic.py
│   └── README.md
├── analysis/               # Statistical analysis
│   └── stats.py
├── tests/                  # Automated tests
├── docs/                   # Project documentation
│   └── Honeypot_Project_Documentation.md
├── docker-compose.lab.yml  # Isolated Docker lab
├── .env.example
├── requirements.txt
└── LICENSE
```

## 🚀 Getting Started

### Requirements

* Python 3.10+
* pip
* Docker (optional, recommended for the isolated lab)

### Running Locally

Install the dependencies:

```bash
pip install -r requirements.txt
```

Create your environment file:

```bash
cp .env.example .env
```

Create the data directory:

```bash
mkdir -p data
```

Start the honeypot:

```bash
python3 -m honeypot.service
```

In another terminal, start the dashboard:

```bash
python3 -m dashboard.app
```

Then open:

```text
http://127.0.0.1:5000
```

### 🧪 Generate Test Traffic

The project includes a traffic simulator so you can safely generate activity against your own honeypot:

```bash
python3 testing/simulate_traffic.py \
    --target 127.0.0.1 \
    --port 2222 \
    --confirm-lab \
    --scenario all
```

After generating some activity, you can run the detection engine:

```bash
python3 -m detection.rules
```

You can also generate statistical reports with:

```bash
python3 -m analysis.stats
```

For more realistic testing, I recommend using the isolated Docker lab described below.

## 🐳 Isolated Lab

For testing scenarios that involve an attacker machine and a honeypot, the project provides an isolated Docker environment.

Create the internal network:

```bash
docker network create --internal honeypot-lab-net
```

Start the lab:

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

You can then access the test attacker container:

```bash
docker exec -it attacker-lab bash
```

From inside the container, you can connect to the honeypot:

```bash
python3 -c "import socket; socket.create_connection(('honeypot', 2222))"
```

The Docker network is configured as an internal network without a route to the public internet.

More detailed setup instructions, including a VM-based lab option, are available in the [project documentation](docs/Honeypot_Project_Documentation.md).

## 🧪 Running Tests

Install pytest if needed:

```bash
pip install pytest
```

Then run:

```bash
pytest
```

The test suite covers the database layer, session and event handling, detection rules, statistics, and security-related scenarios such as SQL injection and XSS payloads.

## 🔐 Security

Security was an important part of the project design.

### Input is never executed

Anything entered into the honeypot—usernames, passwords, or commands—is treated as plain text and stored for analysis. The fake shell never executes commands.

### No real authentication

All authentication attempts fail. There are no real credentials or systems behind the fake service.

### Isolated environment

The Docker lab runs the honeypot as an unprivileged user on an internal network with no internet route.

### SQL injection protection

Database queries use parameterized statements rather than directly building SQL queries from user input. The test suite also includes SQL injection-style payloads to verify this behavior.

### XSS protection

The dashboard uses Flask/Jinja2's automatic HTML escaping to prevent captured input from being interpreted as executable HTML or JavaScript.

### Local access by default

The dashboard binds to `127.0.0.1` by default, and captured passwords are masked unless explicitly revealed.

## 📊 What I Wanted to Learn

This project was built as a practical way to explore several areas of cybersecurity, including:

* Honeypots and deception techniques
* Network monitoring
* Attack detection
* Log collection and analysis
* Python networking
* SQLite database design
* Flask web applications
* Docker-based lab environments
* Secure handling of untrusted input
* Security testing and threat modeling

Rather than just detecting attacks, the goal was to understand the **full process from capturing activity to analyzing it and presenting the results**.

## 📚 Documentation

The full project documentation can be found here:

[Honeypot Project Documentation](docs/Honeypot_Project_Documentation.md)

It includes:

* Project overview
* Threat model
* System architecture
* Database design
* Detection methodology
* Testing methodology
* Results
* Limitations
* Security and ethical considerations
* Future improvements
* Conclusion

## ⚠️ Ethical Considerations

This project is intended for **education, research, and authorized security testing**.

Only run the honeypot in an environment you control or have explicit permission to use. Do not expose it to the public internet without understanding and properly managing the associated risks.

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
