import socket, sys

ALL_PORTS = 65535

TOP_THOUSAND_PORTS = 1024

def port_selection(arg:str):
    ports = []
    # Comma seprated
    if arg.find(',') != -1:
        ports = arg.split(',')
    elif arg.find('-') != -1:
        ports = list(range(int(arg.split('-')[0]), int(arg.split('-')[1]) + 1))
    else:
        ports = [arg]    
    return ports        

def check_open_ports(ip:str, ports:list):
    print(ports)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for port in ports:
        try:
            sock.connect((ip, int(port)))
            sock.send("version".encode("utf-8")[:1024])
            response = sock.recv(1024)
            response = response.decode("utf-8")
            print(port, ": ", response)    

        except:
            continue          
    sock.close()  
    return      

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
            print("Usage: python main.py <IP Address> -p <Port>")
            print("Ports can be single, comma separated, range with - seprated or -p- to specify all ports")
            sys.exit(1)  
    try:
        ports = list(range(0, TOP_THOUSAND_PORTS + 1))  
        if sys.argv[1].startswith("-") == False:
            ip = sys.argv[1]
        if len(sys.argv) > 2: 
            if sys.argv[2].startswith('-p-'):
                ports = list(range(0, ALL_PORTS + 1))
            elif sys.argv[2].startswith('-p'):
                ports = port_selection(sys.argv[3])    
                
    except:
        print("Usage: python main.py <IP Address> -p")
        print("Ports can be single, comma separated, range with - seprated or -p- t0 specify all ports")
        sys.exit(1)        
    check_open_ports(ip, ports)

if __name__ == "__main__":
    main()
