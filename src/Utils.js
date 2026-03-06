export function slugify(str) {
  return str
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-");
}

export function updateBindSerial(zoneFileContent) {
  const today = new Date();
  const yyyy = today.getFullYear();
  const mm = String(today.getMonth() + 1).padStart(2, "0");
  const dd = String(today.getDate()).padStart(2, "0");
  const todayStr = `${yyyy}${mm}${dd}`;

  return zoneFileContent.replace(/(\s+)(\d{10})(\s*;\s*Serial)/,(_, spaces, serial, comment) => {
      const datePart = serial.slice(0, 8);
      const counterPart = serial.slice(8, 10);

      let newSerial;

      if (datePart === todayStr) {
        const newCounter = String(parseInt(counterPart, 10) + 1).padStart(2, "0");
        newSerial = `${todayStr}${newCounter}`;
      } else {
        newSerial = `${todayStr}01`;
      }

      return `${spaces}${newSerial}${comment}`;
    }
  );
}

let cachedKey = null;

export async function getPubKey() {
  if (cachedKey){
    return cachedKey;
  }

  const res = await fetch("http://utils-keys.lake.tryspacelabs.pt/5a71f2d8-cf5a-4922-9b54-71cf9b3020d8.pub");
  cachedKey = await res.text();
  return cachedKey;
}

export function getBearerToken(req) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")){
    return null;
  }
  return h.slice("Bearer ".length).trim();
}

export function isValidDNSName(name) {
  if (typeof name !== "string"){
    return false;
  }

  if (name.endsWith(".")) {
    name = name.slice(0, -1);
  }

  if (name.length === 0 || name.length > 253){
    return false;
  }

  const labels = name.split(".");

  for (const label of labels) {
    if (label.length === 0 || label.length > 63){
      return false;
    }

    if (!/^[a-zA-Z0-9-]+$/.test(label)){
      return false;
    }

    if (label.startsWith("-") || label.endsWith("-")){
      return false;
    }
  }

  return true;
}