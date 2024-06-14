from flask import Flask, render_template, request
import socket
import ipaddress

app = Flask(__name__)

def portScanner(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        if s.connect_ex((ip, port)) == 0:
            return "open"
        else:
            return "closed"
    except Exception as e:
        return f"Error: {e}"
    finally:
        s.close()

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def get_ip_from_domain(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except:
        return None

def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain_name = request.form.get('domain_name', None)
    start_ip = request.form.get('start_ip', None)
    end_ip = request.form.get('end_ip', None)
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    scan_results = {}

    if domain_name:
        ip = get_ip_from_domain(domain_name)
        if ip:
            scan_results[ip] = {'domain_name': domain_name, 'ports': []}
            for port in range(start_port, end_port + 1):
                status = portScanner(ip, port)
                scan_results[ip]['ports'].append({'port': port, 'status': status})
        else:
            return f"Domain name {domain_name} could not be resolved to an IP address."

    elif start_ip:
        if not end_ip:
            end_ip = start_ip

        start_ip_addr = ipaddress.IPv4Address(start_ip)
        end_ip_addr = ipaddress.IPv4Address(end_ip)

        for ip_int in range(int(start_ip_addr), int(end_ip_addr) + 1):
            ip = str(ipaddress.IPv4Address(ip_int))
            domain_name = get_domain_name(ip)  # Get domain name for IP address
            scan_results[ip] = {'domain_name': domain_name, 'ports': []}
            for port in range(start_port, end_port + 1):
                status = portScanner(ip, port)
                scan_results[ip]['ports'].append({'port': port, 'status': status})

    else:
        return "Please provide either a domain name or a start IP address."

    return render_template('result.html', scan_results=scan_results, get_service_name=get_service_name)

if __name__ == '__main__':
    app.run(debug=True)
