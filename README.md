# Komparativna analiza metoda detekcije skeniranja internet aplikacija zasnovanih na mrežnom saobraćaju, HTTP zapisima i njihovoj kombinaciji
 
Ovaj repozitorijum sadrži izvorni kod i skupove podataka korišćene u master radu koji proširuje istraživanje Rajića, Stanisavljevića i Vuletića (2023) dodavanjem HTTP zapisa kao drugog izvora podataka za detekciju DAST skeniranja internet aplikacija.
 
Sirovi podaci, pcap fajlovi i originalni HTTP access logovi, nisu uključeni u repozitorijum zbog veličine; finalni CSV skupovi u `data/` su dovoljni za reprodukciju svih rezultata prikazanih u radu.
 
## Pregled laboratorijskog okruženja
 
Okruženje se sastoji od tri virtuelne mašine sa Ubuntu 20.04 LTS, pokrenute u VirtualBox-u:

| VM | IP адреса | Uloga | Pristup |
|---|---|---|---|
| VM1-DAST | 192.168.56.101 | Izvršavanje DAST skeniranja | sanja / sanja |
| VM2-capture | 192.168.56.102 | Prikupljanje i obrada podataka | sanja / sanja |
| VM3-webapp | 192.168.56.103 | Ciljne internet aplikacije | sanja / sanja |
 
Svaka VM ima host-only mrežni adapter (192.168.56.0/24) i NAT adapter. **Mreža se ne podiže automatski pri pokretanju VM-a** - obavezno prati korake ispod pre svake sesije rada. 

## Podešavanje okruženja pri svakom pokretanju
 
Ovo treba uraditi na **svakoj** od tri VM posle svakog restarta ili pokretanja iz snapshot-a.
 
### 1. Podizanje mrežnih interfejsa
 
Na svakoj VM (VM1, VM2, VM3) pokreni:
 
```bash
sudo ip link set enp0s3 up && sudo dhclient enp0s3
sudo ip link set enp0s8 up && sudo dhclient enp0s8
```
 
> **Kritično**: na VM2 je host-only interfejs `enp0s3`, a **ne** `enp0s8` (to je NAT adapter). Ako mreža deluje aktivna, a `tcpdump` snimke ispadnu prazne ili veličine svega 24 bajta, ovo je najčešći uzrok - proveriti komandom `ip a` da li `enp0s3` zaista ima IP iz opsega 192.168.56.0/24.
 
### 2. Pokretanje Docker kontejnera ciljnih aplikacija (samo na VM3)
 
```bash
docker start webgoat dvwa mutillidae gruyere
```
 
Proveri da li su kontejneri u stanju `Up`:
 
```bash
docker ps
```
 
### 3. Provera Nginx reverse proxy-ja (samo na VM3)
 
```bash
sudo systemctl status nginx
```
 
Ako servis nije aktivan:
 
```bash
sudo systemctl start nginx
```
 
Konfiguracija (`nginx/nginx.conf` u ovom repozitorijumu) definiše četiri `server` bloka, po jedan za svaku aplikaciju, sa preusmerenjem na portove 9080–9083:
 
| Aplikacija | Nginx port | Interni port kontejnera |
|---|---|---|
| WebGoat | 9080 | 8080 |
| DVWA | 9081 | 8081 |
| Mutillidae | 9082 | 8082 |
| Gruyere | 9083 | 8083 (→ 8008 u kontejneru) |
 
## Tok rada (pipeline)
 
Redosled pokretanja skripti za reprodukciju kompletne analize, izvršava se na VM2:
 
### 1a. Prikupljanje malicioznog saobraćaja (DAST skeniranje)
 
Mrežni saobraćaj (pcap) snima se alatom `tcpdump` na VM2, **isključivo na interfejsu `enp0s3`**, neposredno pre pokretanja DAST alata na VM1:
 
```bash
sudo tcpdump -i enp0s3 -w naziv_sesije.pcap
```
 
HTTP zapisi kopiraju se sa VM3 (`/var/log/nginx/*_access.log`) na VM2 posle svake sesije skeniranja, sinhronizovano sa snimanjem pcap-a (detaljan postupak u poglavlju 3.2 rada).
 
### 1b. Generisanje benignog saobraćaja (simulacija korisničkog ponašanja)
 
Paralelno sa snimanjem na VM2 (isti `tcpdump` postupak kao u koraku 1a), na VM1 se pokreće Selenium skripta koja simulira uobičajeno korisničko ponašanje prema sve četiri ciljne aplikacije:
 
```bash
python3 generate_benign_traffic.py
```
 
> Napomena: ovaj korak se izvršava na **VM1** (ne VM2, kao ostatak pipeline-a), gde su prethodno instalirani Chromium i odgovarajući ChromeDriver, iste verzije. `selenium` Python paket takođe treba biti instaliran na VM1 - videti odeljak "Python zavisnosti" ispod.

Skripta izvršava 60 nezavisnih sesija po aplikaciji (ukupno 240), uz nasumične pauze između zahteva radi imitiranja ljudskog tempa pregledanja. HTTP zapisi nastali ovom simulacijom kopiraju se sa VM3 na isti način kao i kod malicioznih sesija. Ovaj korak je neophodan pre prelaska na ekstrakciju karakteristika - bez njega nedostaje benigni HTTP skup potreban za Model B i hibridni skup za Model C.
 
> Napomena: benigni mrežni tokovi za Model A (`final_dataset.csv`) ne potiču iz ove simulacije, već iz CICIDS-2017 skupa podataka (videti poglavlje 3.3.1 rada). Selenium simulacija koristi se isključivo za formiranje HTTP-only i hibridnog benignog skupa, pošto CICIDS-2017 ne sadrži vremenske oznake usklađene sa laboratorijskim okruženjem.
 
### 2. Ekstrakcija karakteristika
 
```bash
# Mrežne karakteristike (za svaki pcap fajl)
python3 scripts/extract_flows.py <putanja_do_pcap> <malicious|benign> <izlazni_csv>
 
# HTTP karakteristike (za svaki access log)
python3 scripts/extract_http_features.py <putanja_do_log_fajla> <malicious|benign> <izlazni_csv>
```
 
Rezultujući CSV fajlovi se spajaju u `final_dataset.csv` (mrežni, Model A) i `http_features_dataset.csv` (HTTP, Model B).
 
### 3. Vremensko usklađivanje (formiranje hibridnog skupa)
 
```bash
python3 scripts/align_datasets.py
```
 
Proizvodi `hybrid_dataset.csv` (Model C) spajanjem agregiranih mrežnih karakteristika sa odgovarajućim HTTP vremenskim prozorom na osnovu izvorne IP adrese i vremenskog preklapanja.
 
### 4. Treniranje i vrednovanje modela
 
```bash
python3 scripts/cross_validate_models.py
```
 
Trenira RF, KNN i SVM nad sva tri skupa podataka primenom 5-fold stratified cross-validation-a; rezultati se čuvaju u `model_results_cv.csv`.
 
### 5. Analiza važnosti karakteristika i po alatu/aplikaciji
 
```bash
python3 scripts/feature_importance_B_v2.py
python3 scripts/feature_importance_C_v2.py
python3 scripts/analyze_per_tool_all_algos.py
```
 
## Instalirani alati i verzije
 
| Alat | Verzija | Napomena |
|---|---|---|
| Nikto | 2.1.5 | - |
| OWASP ZAP | 2.17.0 | - |
| Wapiti | 3.0.4 | Starija verzija (2019); novije zahtevaju mitmproxy ≥ 9.0, nekompatibilno sa Ubuntu 20.04 u ovom okruženju. MITM proxy režim nije podržan, standardni crawl/attack režimi funkcionišu bez ograničenja. |
 
## Python zavisnosti
 
```bash
pip install scapy pandas numpy scikit-learn
```

Uz to, potrebni su i Chromium browser i odgovarajući ChromeDriver (ista verzija), instalirani na nivou operativnog sistema, ne preko pip-a.
 
**Na VM2** (za ekstrakciju karakteristika, usklađivanje i treniranje modela):
 
```bash
pip install scapy pandas numpy scikit-learn
```
 
## Poznati problemi i rešenja
 
Ova sekcija dokumentuje tehničke probleme uočene tokom implementacije, radi uštede vremena pri ponovnom podešavanju okruženja.
 
### Mrežni interfejs enp0s3 vs enp0s8
 
Sva prva snimanja mrežnog saobraćaja bila su prazna (24 bajta) dok nije otkriveno da je host-only interfejs na VM2 zapravo `enp0s3`, a ne `enp0s8` (koji je NAT). Uvek koristiti `-i enp0s3` za `tcpdump`.
 
### Nginx log_format prelom reda
 
Inicijalna `log_format` direktiva bila je fizički prelomljena usred stringa, usled čega su svi logovi pre ispravke bili podeljeni na dva reda. Trenutna konfiguracija (`nginx/nginx.conf`) koristi ispravan jednoredni format, uključujući i `$request_time` polje.
 
### ZAP `-quickurl` zahteva punu putanju
 
Prilikom pokretanja ZAP skeniranja, parametar `-quickurl` mora da sadrži punu putanju (npr. `/WebGoat/login`), a ne samo baznu putanju aplikacije (`/WebGoat`). U suprotnom, alat interno pogrešno parsira URL i pokušava da se poveže na port 80 umesto na ispravan port.
 
### Mutillidae - neusklađena MySQL lozinka
 
Docker image za Mutillidae generiše nasumičnu MySQL lozinku prilikom pokretanja, dok aplikacija očekuje hardkodovanu lozinku `samurai`. Rešeno pokretanjem MySQL u `--skip-grant-tables` režimu i ručnim izvršavanjem:
 
```sql
UPDATE mysql.user SET Password = PASSWORD('samurai') WHERE User = 'root';
FLUSH PRIVILEGES;
```
 
### Gruyere - povremena nestabilnost kontejnera
 
Kontejner povremeno ne odgovara (HTTP 502). HEAD metod nije podržan (vraća 501) - ovo je očekivano ponašanje aplikacije, uvek koristiti GET zahteve.
 
### Wapiti - ograničenje pri autentifikovanom skeniranju
 
Pokušano je povećanje obima podataka za Wapiti primenom cookie-bazirane autentifikacije radi zaobilaženja login barijere na WebGoat i DVWA aplikacijama:
 
1. Ručno uspostavljena autorizovana sesija putem `curl` zahteva, uključujući ispravan CSRF token.
2. Nezavisno potvrđeno da sesija radi (zaštićene stranice dostupne preko istog cookie-ja u običnom HTTP klijentu).
3. I pored toga, Wapiti 3.0.4 crawler nije uspeo da pronađe niti ispita linkove iza login ekrana, ni sa proširenim parametrima (`--scope folder -d 3`), ni posle brisanja keša skeniranja.
Zaključak: dokumentovano ograničenje crawler/HTML parsing logike starije verzije alata, nezavisno od ispravnosti same autorizacije. Ne predstavlja grešku u postupku prikupljanja podataka.
 
## Opis finalnih skupova podataka
 
| Fajl | Model | Broj redova | Maliciozno / Benigno | Karakteristika |
|---|---|---|---|---|
| `final_dataset.csv` | A (mrežni) | 30.056 | 3.560 / 26.496 | 11 (dužina paketa, međuvreme dolaska) |
| `http_features_dataset.csv` | B (HTTP) | 1.444 | 337 / 1.107 | 11 (obim, raznovrsnost, vreme obrade) |
| `hybrid_dataset.csv` | C (hibridni) | 1.444 | 337 / 1.107 | 22 (11 mrežnih + 11 HTTP) |
 
Detaljan opis svake karakteristike nalazi se u poglavlju 3.3 master rada.
 
## Autor
 
Sanja Drobnjak, 3181/2025, Univerzitet u Beogradu Elektrotehnički fakultet

Mentor: dr Žarko Stanisavljević, vanredni profesor
 
Rad predstavlja proširenje: B. Rajić, Ž. Stanisavljević, P. Vuletić, "Early web application attack detection using network traffic analysis," *International Journal of Information Security*, 2023.