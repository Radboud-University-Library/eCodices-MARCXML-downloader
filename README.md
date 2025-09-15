# Ecodices MARC Downloader

Een gebruiksvriendelijke desktop-applicatie om MARC XML-records te downloaden vanuit WorldCat via de Metadata API.

## Beschrijving

De Ecodices MARC Downloader is ontworpen om bibliotheken en andere instellingen te helpen bij het eenvoudig ophalen van MARC-records uit WorldCat. De applicatie biedt een grafische interface waarmee gebruikers:

- WorldCat API-credentials kunnen invoeren voor authenticatie
- OCLC-nummers kunnen invoeren via een CSV-bestand of door deze rechtstreeks te plakken
- De gedownloade records kunnen opslaan in XML-formaat
- De voortgang kunnen volgen via een real-time log en voortgangsindicator

## Installatie

### Vereisten

- Python 3.7 of hoger
- Tkinter
- Bookops-WorldCat
- Requests

### Stappen

1. Clone deze repository of download de ZIP en pak deze uit
   ```
   git clone https://github.com/Radboud-University-Library/eCodices-MARCXML-downloader.git
   cd eCodices-MARCXML-downloader
   ```

2. Maak een virtuele omgeving aan (optioneel maar aanbevolen)
   ```
   python -m venv venv
   ```

3. Activeer de virtuele omgeving
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`

4. Installeer de benodigde packages
   ```
   pip install -r requirements.txt
   ```

5. Start de applicatie
   ```
   python app.py
   ```

## Gebruik

### WorldCat API-credentials

Om deze applicatie te gebruiken, heb je toegang nodig tot de WorldCat Metadata API:

1. Vraag toegang aan via [OCLC Developer Network](https://www.oclc.org/developer/home.en.html)
2. Maak een nieuwe applicatie aan en krijg een WSKey
3. Zorg dat je API Key en Secret beschikbaar hebt

Deze credentials worden alleen tijdens de sessie gebruikt en niet permanent opgeslagen.

### OCLC-nummers invoeren

Je kunt OCLC-nummers op twee manieren invoeren:

1. **CSV-bestand**: Upload een CSV-bestand met een kolom genaamd 'OCLC Number'
2. **Handmatig plakken**: Plak een lijst met OCLC-nummers in het tekstveld (één per regel of gescheiden door komma's of puntkomma's)

### Outputmap

Standaard worden bestanden opgeslagen in een map genaamd `output/[timestamp]` in de huidige directory. Je kunt dit wijzigen door een andere locatie te kiezen.

### Output-bestanden

Na voltooiing van het proces, worden de volgende bestanden gegenereerd:

- XML-bestanden voor elk gedownload record in de map `records/`
- Een ZIP-bestand `marcxml.zip` met alle XML-bestanden
- Een logbestand `run.log` met informatie over het proces
- Een CSV-bestand `errors.csv` met eventuele fouten (indien van toepassing)

## Geavanceerde opties

- **Scope**: Standaard is de scope ingesteld op `WorldCatMetadataAPI`. Wijzig dit alleen als je specifieke behoeften hebt.
- **Pauze tussen verzoeken**: Voeg een pauze toe tussen API-verzoeken (in milliseconden) om rate limiting te voorkomen.
- **Timeout per verzoek**: Stel een timeout-waarde in (in seconden) voor elk API-verzoek. Standaard is dit 15 seconden.


## Problemen oplossen

### Algemene fouten

- **Authenticatiefout**: Controleer of je API Key en Secret correct zijn
- **CSV-fouten**: Zorg ervoor dat je CSV-bestand een kolom met de naam 'OCLC Number' heeft
- **Netwerkfouten**: Controleer je internetverbinding en probeer het opnieuw

### Bekende beperkingen

- De toepassing is onderworpen aan de gebruikslimieten van de WorldCat Metadata API
- Zeer grote batches kunnen lange verwerkingstijden hebben

## Licentie

Dit project is gelicenseerd onder de MIT-licentie - zie het [LICENSE.txt](LICENSE.txt) bestand voor details.

## Contact

Voor vragen of ondersteuning, neem contact op met: ruud.vandenheuvel@ru.nl
