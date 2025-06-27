import dnsclass
import saidas
import argparse
import asyncio

dns = classes.Tools

parser = argparse.ArgumentParser(prog="Horizonrecon", description="")
parser.add_argument("--type", help='''
Escolha a ferramenta que vai utilizar: 
[sub] - Verificar subdominios ativos
[cname] - Checar se os subdominios possuem um alias
''')
parser.add_argument("-d", "--domain", help="Passar o domínio alvo.")
parser.add_argument("-w", "--wordlist", help="Passar a payload de testes.")
parser.add_argument("-t", "--time", type=int, default=10, help="Definir tempo limite por segundo")
parser.add_argument("-o", "--output", help="Salva resultados em um arquivo de texto simples")
args = parser.parse_args()

def Output(tool, file_name):
	if file_name:
		if isinstance(tool, list):
			with open(f"{file_name}", "w") as f:
				for i in tool:
					f.write(i + "\n")
		elif isinstance(tool, dict):
			with open(f"{file_name}", "w") as f:
				for type, info in tool.items():
					f.write(f"{type}:\n")
					for host, ip in info.items():
						f.write(f"{host}: {ip}\n")
		else:
			with open(f"{file_name}", "w") as f:
				f.write(tool)
	else:
		None

if args.type == "cname":
	async def run_check_cname():
		check_cname = dns.CheckCNAME()
		results_cname = await check_cname.Main(args.domain, args.wordlist, args.time)
		for i in results_cname:
			print(i)
		return results_cname
	results_cname = asyncio.run(run_check_cname())
	Output(results_cname, args.output)
elif args.type == "sub":
	async def run_check_subdomain():
		subdomainbf = dns.SubdomainBF()
		results_subdomains = await subdomainbf.Main(args.domain, args.wordlist, args.time)
		for alive in results_subdomains:	
			print(alive)
		return results_subdomains
	results_subdomains = asyncio.run(run_check_subdomain())
	Output(results_subdomains, args.output)
