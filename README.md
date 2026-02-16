# Splunk-n8n-Suricata-Automated-Malicious-URL-Enrichment
## Objective
The goal is to create an n8n workflow that automatically receives a domain name from a Splunk alert, analyzes it using the VirusTotal API, and then triggers different actions — like sending emails, creating ServiceNow tickets, and posting Slack messages — based on the analysis results.

---

## Overview
This README documents a 5-step n8n workflow:

1. Webhook trigger (receives alerts from Splunk)  
2. HTTP Request to VirusTotal (query domain)  
3. Code node (process VirusTotal JSON response into a usable summary)  
4. Switch node (route by `Safe` / `Suspicious`)  
5. Response actions:
   - Gmail (for all alerts)
   - ServiceNow + Slack (for suspicious alerts only)

---

## Prerequisites
- n8n instance (self-hosted or cloud)
- Splunk configured to call an HTTP webhook
- VirusTotal API key
- A Gmail OAuth2 credential in n8n (or other SMTP/email method)
- ServiceNow Basic Auth credential in n8n
- Slack OAuth2 credential in n8n

---

## Step 1: Set up the Webhook Trigger
This node will be the entry point, receiving alerts from Splunk.

1. **Add the Node:** In a new n8n canvas, add a **Webhook** node.  
2. **Configure:**  
   - **Method:** `POST`  
3. **Get the URL:** Copy the **Test URL** from the Webhook node's properties and paste it into the Splunk alert's Webhook action configuration.  
4. **Listen for Data:** Click **Listen for Test Event**. Then, trigger the Splunk alert to send sample JSON to n8n. Once data arrives, you will see it in the Webhook node.  
5. **Connection:** This is the starting node; no incoming connections are needed.

---

## Step 2: Query VirusTotal with HTTP Request
This node takes the domain from the Splunk alert and sends it to the VirusTotal API.

1. **Add the Node:** Add an **HTTP Request** node to the canvas.  
2. **Connect:** Drag the handle from the **Webhook** node to the **HTTP Request** node.  
3. **Configure:**  
   - **Method:** `GET`  
   - **URL:**  
     ```
     https://www.virustotal.com/api/v3/domains/{{ $json.result.domain }}
     ```
     > Explanation: This expression dynamically takes the `domain` field from the JSON payload sent by the Splunk alert (`{{ $json.result.domain }}`).
   - **Authentication:** `Header Auth`  
   - **Credentials:** Select your predefined VirusTotal API credential in n8n. This will add the required `x-apikey` header automatically.

---

## Step 3: Process Data with the Code Node
This node processes the detailed JSON response from VirusTotal into a clean summary object.

1. **Add the Node:** Add a **Code** node.  
2. **Connect:** Drag the handle from the **HTTP Request** node to the **Code** node.  
3. **Configure:**  
   - **Language:** `JavaScript`  
   - **Paste the Code:** Insert the following JavaScript code into the Code node.

~~~javascript
// Extract core attributes from the VirusTotal response
const data = items[0].json.data?.attributes;

const summary = {
  Domain: items[0].json.data?.id || 'N/A',
  Malicious: data?.last_analysis_stats?.malicious || 0,
  Suspicious: data?.last_analysis_stats?.suspicious || 0,
  Undetected: data?.last_analysis_stats?.undetected || 0,
  Harmless: data?.last_analysis_stats?.harmless || 0,
  Categories: (data?.categories && Object.values(data.categories).join(', ')) || 'None',
  Categories_HTML: (data?.categories && Object.values(data.categories).map(cat => `<span class="tag">${cat.trim()}</span>`).join('')) || '',
  Reputation: data?.reputation || 0,
  Registrar: data?.registrar || 'Unknown',
  Registered_Date: data?.creation_date || 'Unknown',
  Expiry_Date: data?.expiration_date || 'Unknown',
  WHOIS_Server: data?.whois_server || 'Unknown',
  Last_Analysis_Date: data?.last_analysis_date ? new Date(data.last_analysis_date * 1000).toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    dateStyle: 'short',
    timeStyle: 'medium',
  }) : 'Unknown',
  Generated_At: new Date().toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    dateStyle: 'short',
    timeStyle: 'medium',
  }),
};

// Determine Status
const status = (summary.Malicious > 0 || summary.Suspicious > 0) ? 'Suspicious' : 'Safe';
summary.Status = status;

return [
  {
    json: {
      summary
    }
  }
];
~~~

> The Code node returns `{{ $json.summary }}` which contains counts and metadata. The `Status` field is `'Suspicious'` if either `Malicious` or `Suspicious` counts are greater than 0; otherwise it's `'Safe'`.

---

## Step 4: Route Logic with the Switch Node
This node directs the workflow based on whether the domain is `Suspicious` or `Safe`.

1. **Add the Node:** Add a **Switch** node.  
2. **Connect:** Drag the handle from the **Code** node to the **Switch** node.  
3. **Configure:**  
   - **Routing Mode:** `Rules`  
   - **Rule 1:**  
     - **Value 1:** `{{ $json.summary.Status }}`  
     - **Operation:** `Equals`  
     - **Value 2:** `Suspicious`  
   - **Result:** This creates two output paths. **Output 0** will be for suspicious domains, and the **Default** output will be for all other domains.

---

## Step 5: Configure the Response Actions

### A. Gmail Notification (For All Alerts)
Sends a detailed HTML report for every domain analyzed.

1. **Add the Nodes:** Add an **HTML** node and a **Gmail** node.  
2. **Connect:**  
   - Connect the **Code** node to the **HTML** node.  
   - Connect the **HTML** node to the **Gmail** node.  
3. **Configure HTML Node:** Paste your HTML report template that references `{{ $json.summary }}` as necessary to render a friendly report.  
4. **Configure Gmail Node:**  
   - **Credentials:** Select your Gmail OAuth2 account.  
   - **To:** Enter recipient email (e.g., `your@mail.com`).  
   - **Subject:**  
     ```
     Security Alert: Domain Analysis for {{ $json.summary.Domain }}
     ```  
   - **Body Type:** `HTML`  
   - **Content:**  
     ```
     {{ $('HTML').item.json.html }}
     ```
     > This expression pulls the rendered HTML from the HTML node.

---

### B. ServiceNow & Slack (For Suspicious Alerts Only)
These actions are triggered only for high-risk domains (Switch output 0).

1. **Add the Nodes:** Add a **ServiceNow** node and a **Slack** node.  
2. **Connect:**  
   - Drag the handle from **Output 0 (Suspicious)** of the **Switch** node to the **ServiceNow** node.  
   - Drag the handle from **Output 0 (Suspicious)** of the **Switch** node to the **Slack** node.  
3. **Configure ServiceNow Node:**  
   - **Credentials:** Select your ServiceNow Basic Auth account.  
   - **Resource:** `Incident`  
   - **Operation:** `Create`  
   - **Fields:** Add a Short description, for example:  
     ```
     Suspicious domain detected: {{ $json.summary.Domain }}
     ```  
   - Add other fields (assignment group, impact, priority, description) as required by your ServiceNow instance.
4. **Configure Slack Node:**  
   - **Credentials:** Select your Slack OAuth2 account.  
   - **Channel:** `#n8n-trigger` (or your desired channel name/ID)  
   - **Text:** craft a message. Example:
     ```
     :rotating_light: *Suspicious Domain Alert* :rotating_light:
     Domain: *{{ $json.summary.Domain }}*
     Status: {{ $json.summary.Status }}
     Malicious Detections: {{ $json.summary.Malicious }}
     ```
   - Optionally format with blocks or attachments for nicer presentation.





