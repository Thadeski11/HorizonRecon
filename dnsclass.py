import socket
import dns.asyncresolver
import asyncio

class Dnsscan():
	class CheckCNAME():
		async def Analyzer(self, url, semaphore):
			async with semaphore:
				try:
					await asyncio.sleep(1)
					resolver = dns.asyncresolver.Resolver()
					resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
					response = await resolver.resolve(url, "CNAME")
					cname = str(response[0].target)
					return url, cname
				except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
					return url, None
				except dns.resolver.LifetimeTimeout:
					await asyncio.sleep(1)
					return url, None

		async def Main(self, domain, wordlist, timed=10):
			semaphore = asyncio.Semaphore(timed)
			urls = []
			results = []
			with open(wordlist, "r") as w:
				for i in w:
					i = i.strip()
					url_montada = f"{i}.{domain}"
					urls.append(url_montada)
			
			tasks = [self.Analyzer(url, semaphore) for url in urls]
			tasks_done = await asyncio.gather(*tasks)
			for url, cname in tasks_done:
				if cname:
					results.append(f"[{url}] aponta para o CNAME: [{cname}]")
					
	
			return results

	class SubdomainBF():
		async def DNSipv4(self, subdomain, semaphore):
			async with semaphore:
				try:
					loop = asyncio.get_running_loop()
					dados = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None, socket.AF_INET)
					addr = dados[2][4][0]
					return subdomain, addr
				except (socket.gaierror, UnicodeError):
					return subdomain, None

		async def DNSipv6(self, subdomain, semaphore):
			async with semaphore:
				try:
					loop = asyncio.get_running_loop()
					dados = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None, socket.AF_INET6)
					addr = dados[2][4][0]
					return subdomain, addr
				except (socket.gaierror, UnicodeError):
					return subdomain, None


		async def Main(self, domain, wordlist, timed=10, ipv4_6=None):
			semaphore = asyncio.Semaphore(timed)

			subdomains = []
			subdomains_4 = {}
			subdomains_6 = {}
			subdomains_done = {}

			with open(wordlist, "r") as f:
				for i in f:
					i = i.strip()
					subdomain_ass = f"{i}.{domain}"
					subdomains.append(subdomain_ass)

			if ipv4_6 == "4" or ipv4_6 == None:
				addr4 = [self.DNSipv4(subdomain, semaphore) for subdomain in subdomains]
				tasks4_done = await asyncio.gather(*addr4)
				for subdomain, addr in tasks4_done:
					if addr:
						subdomains_4[subdomain] = addr
			elif ipv4_6 == "6":
				addr6 = [self.DNSipv6(subdomain, semaphore) for subdomain in subdomains] 
				tasks6_done = await asyncio.gather(*addr6)
				for subdomain, addr in tasks6_done:
					if addr:
						subdomains_6[subdomain] = addr	
			elif ipv4_6 == "all":
				addr4 = [self.DNSipv4(subdomain, semaphore) for subdomain in subdomains]
				addr6 = [self.DNSipv6(subdomain, semaphore) for subdomain in subdomains]
				tasks4_done = await asyncio.gather(*addr4)
				tasks6_done = await asyncio.gather(*addr6)
				for subdomain, addr in tasks4_done:
					if addr:
						subdomains_4[subdomain] = addr
				for subdomain, addr in tasks6_done:
					if addr:
						subdomains_6[subdomain] = addr


			subdomains_done["ipv4"] = subdomains_4
			subdomains_done["ipv6"] = subdomains_6
			return subdomains_done

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
