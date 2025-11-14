let lastResults = [];

async function findSubdomains() {
    const domain = document.getElementById("domainInput").value;
    const ul = document.getElementById("subResults");
    const progress = document.getElementById("progress");

    progress.classList.remove("hidden");
    ul.innerHTML = "";

    const res = await fetch("/api/subdomains", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain})
    });

    const data = await res.json();
    lastResults = data.subdomains;

    progress.classList.add("hidden");

    data.subdomains.forEach(s => {
        const li = document.createElement("li");
        li.textContent = s.subdomain;
        const img = document.createElement("img");
        img.src = s.screenshot;
        li.appendChild(img);
        ul.appendChild(li);
    });
}

async function lookupDNS() {
    const domain = document.getElementById("domainInput").value;
    const area = document.getElementById("dnsResult");

    const res = await fetch("/api/dns", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain})
    });

    const data = await res.json();
    area.textContent = JSON.stringify(data, null, 2);
}

async function lookupWHOIS() {
    const domain = document.getElementById("domainInput").value;
    const area = document.getElementById("whoisResult");

    const res = await fetch("/api/whois", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({domain})
    });

    const data = await res.json();
    area.textContent = JSON.stringify(data, null, 2);
}

async function exportTXT() {
    await fetch("/export/txt", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({subdomains: lastResults})
    }).then(res => res.blob()).then(downloadBlob);
}

async function exportCSV() {
    await fetch("/export/csv", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({subdomains: lastResults})
    }).then(res => res.blob()).then(downloadBlob);
}

function downloadBlob(blob) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "export";
    a.click();
}

function toggleTheme() {
    document.body.classList.toggle("light");
}
