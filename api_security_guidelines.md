# Secure AI Integration Architecture for Browser Extensions

When building browser extensions that rely on third-party APIs (like OpenAI, Hugging Face, or VirusTotal), a primary concern is protecting your API keys from being leaked and preventing staggering billing costs. 

Because a browser extension's code (HTML, CSS, JavaScript) runs entirely on the client's computer, **anyone can easily view your source code and steal your API key if you hardcode it into the extension.** 

To prevent your API key from being leaked, here is the industry-standard way you should architect the integration for your capstone project:

## 1. Never put the API Key in the Extension
You must absolutely never write your API keys anywhere in your extension's JavaScript files. 

## 2. Build a "Backend Proxy Server" (The Right Way)
Instead of the extension talking directly to the AI, you need a middleman. You should build a very lightweight backend server (using Node.js, Python/Flask, or free Serverless functions like Vercel or AWS Lambda).
*   **Step A:** The user clicks an email. The browser extension sends the email text to **your backend server**.
*   **Step B:** Your backend server holds your API key securely hidden in a `.env` (environment variable) file on the server. 
*   **Step C:** Your backend server makes the secure request to the AI API using the hidden key.
*   **Step D:** The AI replies to your backend, and your backend forwards the final analysis back to the browser extension.

## 3. Protect Your Backend (Rate Limiting & Auth)
Even with a backend, if someone finds your backend URL, they could spam it and run up your AI bill. You must implement:
*   **Authentication:** Force users to log in to the extension (e.g., using Firebase Auth). Your backend should only accept requests that include a valid user token.
*   **Rate Limiting:** Set a strict limit on your backend (e.g., maximum 50 emails analyzed per user, per day). If they hit the limit, your backend simply rejects the request before it ever reaches the paid AI API.
*   **API Billing Limits:** Most providers allow you to set a "Hard Cap" in your billing settings. Set your hard cap to $5 or $10 so that even if the worst happens, your API turns off before you get a surprise bill.

## 4. Capstone Budget Hack: Use Free Models
Since this is a capstone project, you might not want to pay for an API at all. In your paper, you mentioned using models like **BERT** or **DistilBERT**. 
*   Instead of using a paid API like ChatGPT, you can host a pre-trained DistilBERT model on a free tier service like **Hugging Face Inference API** or **Render**. 
*   Hugging Face provides generous free tiers for researchers and students, which completely eliminates the risk of a surprise bill while perfectly fitting your project's methodology.

---

### Summary for your Capstone Defense:
If the panel asks how you plan to secure the AI integration and manage costs, tell them: 
> *"We will utilize a secure backend proxy architecture where the API keys are stored safely as environment variables on the server. The browser extension will only communicate with our backend, which will enforce strict authentication and rate-limiting to prevent API abuse and cost overruns."*
