const API_BASE_URL = "";

export async function analyzePcap(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload-pcap`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `Upload failed: ${response.status}`);
  }

  return response.json();
}

export async function uploadPcap(file) {
  return analyzePcap(file);
}

export async function getResults(analysisId) {
  const response = await fetch(
    `${API_BASE_URL}/results/${analysisId}`
  );

  if (!response.ok) {
    throw new Error(`Failed to get results: ${response.status}`);
  }

  return response.json();
}

export async function getReportJson(analysisId) {
  const response = await fetch(
    `${API_BASE_URL}/report/${analysisId}/json`
  );

  if (!response.ok) {
    throw new Error(`Failed to get report: ${response.status}`);
  }

  return response.json();
}

export function getReportHtmlUrl(analysisId) {
  return `${API_BASE_URL}/report/${analysisId}/html`;
}

export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error("Backend is not healthy");
  }

  return response.json();
}
