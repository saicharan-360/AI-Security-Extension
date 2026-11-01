const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// CRC32 implementation for PNG chunks
const crcTable = [];
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  crcTable[n] = c >>> 0;
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = (crcTable[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function makePng(width, height, renderPixel) {
  // 1 byte filter (0 = None) + 4 bytes RGBA per pixel
  const rowSize = 1 + width * 4;
  const rawData = Buffer.alloc(height * rowSize);

  for (let y = 0; y < height; y++) {
    const rowOffset = y * rowSize;
    rawData[rowOffset] = 0; // Filter: None
    for (let x = 0; x < width; x++) {
      const [r, g, b, a] = renderPixel(x, y, width, height);
      const pixelOffset = rowOffset + 1 + x * 4;
      rawData[pixelOffset] = r;
      rawData[pixelOffset + 1] = g;
      rawData[pixelOffset + 2] = b;
      rawData[pixelOffset + 3] = a;
    }
  }

  const deflated = zlib.deflateSync(rawData);

  // PNG Header
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData.writeUInt8(8, 8); // bit depth 8
  ihdrData.writeUInt8(6, 9); // RGBA color type
  ihdrData.writeUInt8(0, 10); // compression
  ihdrData.writeUInt8(0, 11); // filter
  ihdrData.writeUInt8(0, 12); // interlace

  function makeChunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([len, typeBuf, data, crcBuf]);
  }

  const ihdrChunk = makeChunk('IHDR', ihdrData);
  const idatChunk = makeChunk('IDAT', deflated);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

// Security Shield pixel renderer
function renderShield(x, y, w, h) {
  const nx = (x / (w - 1)) * 2 - 1; // -1 to +1
  const ny = (y / (h - 1)) * 2 - 1; // -1 to +1

  // Outer shield boundary
  // Top curve / crown: ny < -0.6
  // Bottom taper: abs(nx) < 0.85 - (ny + 0.3) * 0.75 for ny >= -0.3
  const absX = Math.abs(nx);
  
  let inOuter = false;
  if (ny >= -0.85 && ny <= 0.9) {
    let allowedWidth = 0.85;
    if (ny < -0.7) {
      // Top dip
      allowedWidth = 0.85 - ((-0.7 - ny) * 0.5);
    } else if (ny > -0.2) {
      // Bottom triangle taper
      allowedWidth = 0.85 * (1 - (ny + 0.2) / 1.1);
    }
    if (absX <= allowedWidth) {
      inOuter = true;
    }
  }

  if (!inOuter) return [0, 0, 0, 0]; // Transparent outside shield

  // Check if near border (dark border / glow)
  let allowedInner = 0.75;
  if (ny < -0.65) {
    allowedInner = 0.75 - ((-0.65 - ny) * 0.5);
  } else if (ny > -0.15) {
    allowedInner = 0.75 * (1 - (ny + 0.15) / 1.05);
  }

  const inInner = (ny >= -0.75 && ny <= 0.8 && absX <= allowedInner);

  // Checkmark inside shield
  // Checkmark segments: (-0.4, 0.0) -> (-0.1, 0.3) -> (0.45, -0.25)
  let inCheck = false;
  const stroke = w <= 16 ? 0.22 : (w <= 32 ? 0.16 : 0.12);

  // Segment 1: from (-0.35, 0.05) to (-0.08, 0.32)
  const d1 = distToSegment(nx, ny, -0.35, 0.05, -0.08, 0.32);
  // Segment 2: from (-0.08, 0.32) to (0.42, -0.22)
  const d2 = distToSegment(nx, ny, -0.08, 0.32, 0.42, -0.22);

  if (d1 < stroke || d2 < stroke) {
    inCheck = true;
  }

  if (inCheck) {
    return [255, 255, 255, 255]; // Crisp white checkmark
  }

  if (inInner) {
    // Beautiful cyan-to-electric-blue gradient
    const t = (ny + 0.8) / 1.6;
    const r = Math.round(14 * (1 - t) + 37 * t);
    const g = Math.round(165 * (1 - t) + 99 * t);
    const b = Math.round(233 * (1 - t) + 235 * t);
    return [r, g, b, 255];
  }

  // Dark shield border
  return [15, 23, 42, 255];
}

function distToSegment(px, py, x1, y1, x2, y2) {
  const l2 = (x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1);
  if (l2 === 0) return Math.hypot(px - x1, py - y1);
  let t = ((px - x1) * (x2 - x1) + (py - y1) * (y2 - y1)) / l2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * (x2 - x1)), py - (y1 + t * (y2 - y1)));
}

const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

[16, 32, 48, 128].forEach(size => {
  const pngBuf = makePng(size, size, renderShield);
  fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), pngBuf);
  console.log(`Generated icon${size}.png (${size}x${size}, ${pngBuf.length} bytes)`);
});
