import socket
import dns.resolver
import time

class Dnsscan():
	def CheckCNAME(dominio, wordlist):
		resultados_cname = {}

		with open(wordlist) as f:
			for i in f.readlines():
				i = i.replace("\n", "")
				montado = f"{i}.{dominio}"

				while True:
					try:
						resposta = dns.resolver.resolve(montado, "CNAME")
						cname = str(resposta[0].target)
						print(f"{montado} tem um alias {cname}")
						resultados_cname[montado] = cname
						break
					except dns.resolver.NoAnswer:
						break
					except dns.resolver.NXDOMAIN:
						break
					except dns.resolver.LifetimeTimeout:
						print("Caiu no timeout")
						time.sleep(2)
		return resultados_cname

	def SubdomainBF(dominio, wordlist, ipv4_6=None):
		def DNSipv4(dominio_montado):
			try:
				dados = socket.getaddrinfo(dominio_montado, None, socket.AF_INET)
				addr = dados[2][4][0]

				print(f"{dominio_montado} --- {addr}")
				return addr
			except socket.gaierror:
				return 0


		def DNSipv6(dominio_montado):
			try:
				dados = socket.getaddrinfo(dominio_montado, None, socket.AF_INET6)
				addr = dados[2][4][0]

				print(f"{dominio_montado} --- {addr}")
				return addr
			except socket.gaierror:
				return 0


		consultado = []
		dominios4 = {}
		dominios6 = {}
		dominios = {}

		with open(wordlist) as f:
			for i in f.readlines():
				i = i.replace("\n", "")
				dominio_montado = f"{i}.{dominio}"
				if dominio_montado not in consultado:
					if ipv4_6 == "4" or ipv4_6 == None:
						addr4 = DNSipv4(dominio_montado)
						consultado.append(dominio_montado)

						if addr4 != 0:
							dominios4[dominio_montado] = addr4
					elif ipv4_6 == "6":
						addr6 = DNSipv6(dominio_montado)
						consultado.append(dominio_montado)

						if addr6 != 0:
							dominios6[dominio_montado] = addr6
					elif ipv4_6 == "all":
						addr4 = DNSipv4(dominio_montado)
						addr6 = DNSipv6(dominio_montado)
						consultado.append(dominio_montado)

						if addr4 != 0:
							dominios4[dominio_montado] = addr4
						if addr6 != 0:
							dominios6[dominio_montado] = addr6


		dominios["ipv4"] = dominios4
		dominios["ipv6"] = dominios6
		return dominios

	def Whois(dominio):
		def openSocket(d, data):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((d,43))
			s.send(data.encode())
			return s


		d = dominio + "\r\n"

		s = openSocket("whois.iana.org", d)
		whois1 = s.recv(1024).decode().split("refer:        ")[1].split("\n")[0]
		s.close() 

		s = openSocket(whois1, d)
		whois2 = s.recv(1024).decode().split("Registrar WHOIS Server: ")[1].split("\r")[0]
		s.close

		s = openSocket(whois2, d)

		resposta = ""
		while True:
			data = s.recv(8024)
			if data:
				resposta += data.decode()
			else:
				break

		print(resposta)
		return resposta
