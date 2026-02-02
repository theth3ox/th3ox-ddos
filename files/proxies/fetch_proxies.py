#!/usr/bin/env python3
import requests
from pathlib import Path

def fetch_proxies():
    """Ücretsiz proxy listelerini çeker ve http.txt dosyasına kaydeder"""
    
    sources = [
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    ]
    
    all_proxies = set()
    
    print("Proxy'ler çekiliyor...")
    
    for url in sources:
        try:
            print(f"Kaynak: {url[:50]}...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                proxies = response.text.strip().split('\n')
                # Sadece IP:PORT formatındakileri al
                for proxy in proxies:
                    proxy = proxy.strip()
                    if ':' in proxy and not proxy.startswith('#'):
                        all_proxies.add(proxy)
                print(f"✓ {len(proxies)} proxy bulundu")
        except Exception as e:
            print(f"✗ Hata: {e}")
    
    # Dosyaya kaydet
    output_file = Path(__file__).parent / "http.txt"
    with open(output_file, 'w') as f:
        for proxy in sorted(all_proxies):
            f.write(f"{proxy}\n")
    
    print(f"\n✓ Toplam {len(all_proxies)} proxy kaydedildi: {output_file}")
    print(f"Kullanım: Proxy dosya adı olarak 'http.txt' yazın")

if __name__ == "__main__":
    fetch_proxies()
