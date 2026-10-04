const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ||
  "https://securemailscope-m6-2.onrender.com"
).replace(/\/$/, "");

async function parseResponse(response) {
  const text = await response.text();

  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }

  if (!response.ok) {
    throw new Error(
      data?.detail ||
        data?.message ||
        `Request failed with status ${response.status}`
    );
  }

  return data;
}

export async function analyzePcap(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload-pcap`, {
    method: "POST",
    body: formData,
  });

  return parseResponse(response);
}

export async function uploadPcap(file) {
  return analyzePcap(file);
}

export async function getResults(analysisId) {
  if (!analysisId) {
    throw new Error("Analysis ID is required.");
  }

  const response = await fetch(`${API_BASE_URL}/results/${analysisId}`);
  return parseResponse(response);
}

export async function getReportJson(analysisId) {
  if (!analysisId) {
    throw new Error("Analysis ID is required.");
  }

  const response = await fetch(
    `${API_BASE_URL}/report/${analysisId}/json`
  );
  return parseResponse(response);
}

export function getReportHtmlUrl(analysisId) {
  return `${API_BASE_URL}/report/${analysisId}/html`;
}

export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  return parseResponse(response);
}

export { API_BASE_URL };
