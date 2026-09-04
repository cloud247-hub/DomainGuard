# DomainGuard

DomainGuard er en statisk webapp for kontroll av DNS- og e-postsikkerhet for et domene.

Appen kjører direkte i nettleseren og gjør offentlige DNS-oppslag via DNS-over-HTTPS. Det kreves ingen konto, backend eller API-nøkkel.

## Funksjoner

DomainGuard kontrollerer blant annet:

- DNSSEC
- MX
- SPF
- DKIM
- DMARC
- MTA-STS
- SMTP TLS-RPT
- CAA
- BIMI
- A / AAAA
- NS / SOA

Resultatene vises med forklaringer og anbefalinger på norsk og engelsk.

## Forbedret DKIM-deteksjon

DKIM-selectorer er ikke standardiserte, og det finnes ingen generell DNS-mekanisme for å liste alle DKIM-selectorer et domene bruker.

Denne versjonen av DomainGuard bruker derfor flere metoder for å gi bedre DKIM-dekning:

- Provider-detection basert på MX, NS og SPF
- Leverandørspesifikke DKIM-selectorer
- Utvidet liste med vanlige selectorer
- Oppslag av både TXT og CNAME
- Følger CNAME-kjeder frem til faktisk DKIM-record
- Validerer DKIM-recorden når den blir funnet
- Skiller mellom bekreftet DKIM, feilkonfigurasjon og ukjent selector

DomainGuard tester opptil 48 relevante DKIM-selectorer per domene.

### DKIM-status

**DKIM konfigurert**

Minst én gyldig DKIM-record er funnet og validert.

**DKIM kunne ikke bekreftes**

Ingen kjent selector ble funnet. Dette betyr ikke nødvendigvis at DKIM mangler. Domenet kan bruke en egendefinert eller tilfeldig selector.

**DKIM-feil**

En DKIM-record ble funnet, men recorden er ugyldig, feilkonfigurert eller nøkkelen er tilbakekalt.

## Domeneshop

DomainGuard har egen deteksjon for Domeneshop.

Når domenet bruker:

- Domeneshop som e-postleverandør via MX
- Domeneshop sine autoritative navneservere

kan DomainGuard identifisere at domenet bruker Domeneshop sitt automatiske e-postoppsett.

Typisk oppsett:

```text
MX:
mx.domeneshop.no

NS:
ns1.hyp.net
ns2.hyp.net
ns3.hyp.net
```

Når både MX og autoritative NS matcher Domeneshop, vises DKIM som:

```text
DKIM aktivert
Leverandør: Domeneshop
Verifisering: Leverandøradministrert
```

DomainGuard forsøker fortsatt å finne DKIM-recorden der det er relevant, men et manglende treff på en kjent selector skal ikke gi en falsk negativ DKIM-advarsel for et komplett Domeneshop-oppsett.

Hvis bare MX eller bare NS peker til Domeneshop, blir DKIM ikke automatisk godkjent.

## Støttede leverandørprofiler

DomainGuard kjenner igjen vanlige e-postplattformer, blant annet:

- Microsoft 365
- Google Workspace
- Domeneshop
- Brevo
- Twilio SendGrid
- Mailgun
- Postmark
- Amazon SES
- Mailchimp / Mandrill

Provider-detection brukes til å prioritere relevante DKIM-selectorer. Det brukes ikke alene som bevis på at DKIM er konfigurert, med unntak av kjente leverandøradministrerte oppsett som Domeneshop-regelen over.

## Manuell DKIM-selector

Hvis du kjenner DKIM-selectoren, kan den legges inn manuelt i DomainGuard.

Eksempel:

```text
selector1
```

DomainGuard kontrollerer da:

```text
selector1._domainkey.example.no
```

Dette er den mest presise DNS-baserte testen når selectoren er kjent.

## Viktig begrensning

Det er ikke mulig å garantere 100 % DKIM-deteksjon kun ved å skanne DNS.

En avsender kan bruke:

- egendefinert selector
- tilfeldig generert selector
- flere forskjellige e-postleverandører
- separate selectorer for ulike tjenester eller subdomener

En manglende selector i DomainGuard betyr derfor ikke automatisk at domenet mangler DKIM.

Den sikreste måten å identifisere aktiv DKIM-selector på er å analysere en faktisk sendt e-post og lese `s=`-verdien fra `DKIM-Signature`-headeren.

## Personvern

DomainGuard har ingen egen backend for domeneoppslag.

Domenet som brukeren skriver inn sendes til offentlig DNS-resolver for å kunne gjøre DNS-oppslag.

Ingen rapporter eller domenedata lagres av DomainGuard.

## Teknisk arkitektur

DomainGuard er bygget som en statisk webapp og kan publiseres direkte med GitHub Pages.

Hovedfiler:

```text
index.html
styles.css
cloud247-theme.css
app.js
i18n.js
CNAME
.nojekyll
README.md
```

DNS-oppslag gjøres fra JavaScript i nettleseren.

## Publisering med GitHub Pages

1. Last opp filene til repository-roten.
2. Åpne **Settings → Pages** i GitHub.
3. Velg **Deploy from a branch**.
4. Velg branch `main`.
5. Velg `/(root)`.
6. Lagre.
7. Aktiver **Enforce HTTPS** når sertifikatet er klart.

Produksjonsdomene:

```text
https://domainguard.cloud247.no/
```

## Oppdatering fra forrige versjon

For DKIM-oppdateringen er følgende filer endret:

```text
app.js
i18n.js
```

De øvrige frontend-filene kan beholdes dersom du allerede kjører den nåværende DomainGuard-versjonen.

## Språk

DomainGuard støtter norsk og engelsk.

Valgt språk lagres lokalt i nettleseren.

Språk kan også velges via URL:

```text
?lang=no
?lang=en
```

## Ansvarsfraskrivelse

DomainGuard er et diagnostikkverktøy basert på offentlige DNS-data.

Resultatene viser konfigurasjonen slik den kan observeres på tidspunktet testen kjøres. DNS-cache, propagasjon, leverandørspesifikke oppsett og ukjente DKIM-selectorer kan påvirke resultatet.

Endringer i DNS bør alltid kontrolleres mot dokumentasjonen til den aktuelle DNS- eller e-postleverandøren.
