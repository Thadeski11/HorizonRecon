import socket
import time
import asyncio
import dns.asyncresolver

class Tools():
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
		async def DNS(self, subdomain, semaphore):
			async with semaphore:
				try:
					loop = asyncio.get_running_loop()
					dados = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None, socket.AF_INET)
					addr = dados[2][4][0]
					return subdomain, addr
				except (socket.gaierror, UnicodeError):
					return subdomain, None

		async def Main(self, domain, wordlist, timed=10):
			semaphore = asyncio.Semaphore(timed)

			subdomains = []
			subdomains_done = []

			with open(wordlist, "r") as f:
				for i in f:
					i = i.strip()
					subdomain_test = f"{i}.{domain}"
					subdomains.append(subdomain_test)

			addr = [self.DNS(subdomain, semaphore) for subdomain in subdomains]
			tasks_done = await asyncio.gather(*addr)
			for subdomain, ip in tasks_done:
				if ip:
					subdomains_done.append(subdomain)

			return subdomains_done
