import { CartItem } from "@/contexts/CartContext";

export interface PDFConfig {
  companyName?: string;
  companyEmail?: string;
  companyPhone?: string;
  customerName?: string;
  customerPhone?: string;
  invoiceNumber?: string;
  taxRate?: number;
  currency?: string;
  pricePerGb?: number;
  headerImage?: string;
  footerText?: string;
  invoiceLabel?: string;
}

export const generatePDF = async (
  items: CartItem[],
  totalSize: string,
  totalPrice: number,
  config: PDFConfig = {}
): Promise<void> => {
  const { default: jsPDF } = await import("jspdf");
  const pdf = new jsPDF();
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();

  const {
    companyName = "GAMEARLY",
    companyEmail = "gamearly@gmail.com",
    companyPhone = "01559665337",
    customerName = "",
    customerPhone = "",
    invoiceNumber = `ORD-${Date.now().toString().slice(-6)}`,
    currency = "EGP",
    pricePerGb = 0.20,
    footerText = "Thank you for your order! Contact us on WhatsApp for download details.",
    invoiceLabel = "ORDER RECEIPT",
  } = config;

  // Colors — Navy Dark theme
  const navy: [number, number, number] = [13, 18, 38];
  const iceBlue: [number, number, number] = [56, 189, 248];
  const green: [number, number, number] = [74, 222, 128];
  const silver: [number, number, number] = [148, 163, 184];
  const white: [number, number, number] = [255, 255, 255];
  const lightGray: [number, number, number] = [241, 245, 249];
  const textDark: [number, number, number] = [15, 23, 42];
  const textMid: [number, number, number] = [71, 85, 105];

  let y = 0;

  // ── HEADER BANNER ──────────────────────────────────────────────────────────
  pdf.setFillColor(...navy);
  pdf.rect(0, 0, pageWidth, 52, "F");

  pdf.setFillColor(...iceBlue);
  pdf.rect(0, 0, 4, 52, "F");

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(22);
  pdf.setTextColor(...white);
  pdf.text(companyName, 14, 22);

  pdf.setFontSize(9);
  pdf.setTextColor(...iceBlue);
  pdf.text(invoiceLabel, 14, 33);

  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(8);
  pdf.setTextColor(...silver);
  pdf.text(companyEmail, pageWidth - 14, 20, { align: "right" });
  pdf.text(companyPhone, pageWidth - 14, 28, { align: "right" });

  y = 62;

  // ── ORDER INFO ─────────────────────────────────────────────────────────────
  const orderDate = new Date().toLocaleDateString("en-GB");
  const orderTime = new Date().toLocaleTimeString();

  pdf.setFillColor(...lightGray);
  pdf.roundedRect(14, y - 6, pageWidth - 28, 28, 3, 3, "F");

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(9);
  pdf.setTextColor(...textMid);
  pdf.text("ORDER NUMBER", 20, y + 2);
  pdf.text("DATE", 80, y + 2);
  pdf.text("TIME", 130, y + 2);

  pdf.setFontSize(11);
  pdf.setTextColor(...textDark);
  pdf.text(invoiceNumber, 20, y + 12);
  pdf.text(orderDate, 80, y + 12);
  pdf.text(orderTime, 130, y + 12);

  y += 36;

  // ── CUSTOMER INFO ──────────────────────────────────────────────────────────
  if (customerName || customerPhone) {
    pdf.setFillColor(...navy);
    pdf.rect(14, y - 5, pageWidth - 28, 10, "F");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(9);
    pdf.setTextColor(...iceBlue);
    pdf.text("CUSTOMER INFORMATION", 18, y + 1);

    y += 14;
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(10);
    pdf.setTextColor(...textDark);

    if (customerName) {
      pdf.setFont("helvetica", "bold");
      pdf.setTextColor(...textMid);
      pdf.text("Name:", 18, y);
      pdf.setFont("helvetica", "normal");
      pdf.setTextColor(...textDark);
      pdf.text(customerName, 45, y);
      y += 8;
    }
    if (customerPhone) {
      pdf.setFont("helvetica", "bold");
      pdf.setTextColor(...textMid);
      pdf.text("Phone:", 18, y);
      pdf.setFont("helvetica", "normal");
      pdf.setTextColor(...textDark);
      pdf.text(customerPhone, 45, y);
      y += 8;
    }
    y += 6;
  }

  // ── GAMES TABLE HEADER ─────────────────────────────────────────────────────
  pdf.setFillColor(...navy);
  pdf.rect(14, y - 5, pageWidth - 28, 12, "F");

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(9);
  pdf.setTextColor(...white);

  const col = { num: 18, name: 30, size: 148, price: 168, qty: 192 };
  pdf.text("#", col.num, y + 2);
  pdf.text("GAME NAME", col.name, y + 2);
  pdf.text("SIZE", col.size, y + 2);
  pdf.text("PRICE", col.price, y + 2);
  pdf.text("QTY", col.qty, y + 2);

  y += 14;

  // ── GAME ROWS ──────────────────────────────────────────────────────────────
  items.forEach((item, index) => {
    if (y > pageHeight - 60) {
      pdf.addPage();
      y = 20;
    }

    if (index % 2 === 0) {
      pdf.setFillColor(248, 250, 252);
      pdf.rect(14, y - 5, pageWidth - 28, 9, "F");
    }

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(9);

    pdf.setTextColor(...textMid);
    pdf.text(String(index + 1), col.num, y);

    pdf.setTextColor(...textDark);
    const gameName =
      item.title.length > 58 ? item.title.substring(0, 55) + "..." : item.title;
    pdf.text(gameName, col.name, y);

    pdf.setFont("helvetica", "bold");
    pdf.setTextColor(...iceBlue);
    pdf.text(item.size, col.size, y);

    const itemGB = parseFloat(item.size.replace(/[^0-9.]/g, ""));
    const itemPrice = isNaN(itemGB) ? 0 : itemGB * pricePerGb * item.quantity;
    pdf.setTextColor(...green);
    pdf.text(`${itemPrice.toFixed(2)}`, col.price, y);

    pdf.setFont("helvetica", "normal");
    pdf.setTextColor(...textDark);
    pdf.text(item.quantity.toString(), col.qty, y);

    y += 9;
  });

  // ── TOTALS ─────────────────────────────────────────────────────────────────
  y += 6;
  pdf.setDrawColor(...iceBlue);
  pdf.setLineWidth(0.6);
  pdf.line(14, y, pageWidth - 14, y);
  y += 8;

  pdf.setFillColor(...lightGray);
  pdf.roundedRect(pageWidth - 100, y - 5, 86, 34, 3, 3, "F");

  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(9);
  pdf.setTextColor(...textMid);
  pdf.text(`Total Games: ${items.reduce((s, i) => s + i.quantity, 0)}`, pageWidth - 96, y + 2);

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(10);
  pdf.setTextColor(...navy);
  pdf.text(`Total Size: ${totalSize}`, pageWidth - 96, y + 12);

  pdf.setFontSize(11);
  pdf.setTextColor(20, 140, 60);
  pdf.text(`Total Price: ${totalPrice.toFixed(2)} ${currency}`, pageWidth - 96, y + 22);

  // ── FOOTER ─────────────────────────────────────────────────────────────────
  pdf.setFillColor(...navy);
  pdf.rect(0, pageHeight - 18, pageWidth, 18, "F");
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(7.5);
  pdf.setTextColor(...silver);
  const footerLines = pdf.splitTextToSize(footerText, pageWidth - 30);
  pdf.text(footerLines, 14, pageHeight - 9);

  pdf.save(`${companyName}_Order_${invoiceNumber}.pdf`);
};

export const buildWhatsAppMessage = (
  items: CartItem[],
  totalSize: string,
  totalPrice: number,
  config: PDFConfig = {}
): string => {
  const {
    companyName = "GAMEARLY",
    customerName = "",
    customerPhone = "",
    invoiceNumber = `ORD-${Date.now().toString().slice(-6)}`,
    currency = "EGP",
  } = config;

  const date = new Date().toLocaleDateString("en-GB");
  const time = new Date().toLocaleTimeString();

  let msg = `🎮 *NEW ORDER — ${companyName}*\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  msg += `📋 *Order #:* ${invoiceNumber}\n`;
  msg += `📅 *Date:* ${date}   🕐 ${time}\n\n`;

  if (customerName || customerPhone) {
    msg += `👤 *CUSTOMER:*\n`;
    if (customerName) msg += `• Name: ${customerName}\n`;
    if (customerPhone) msg += `• Phone: ${customerPhone}\n`;
    msg += `\n`;
  }

  msg += `🎯 *GAMES ORDERED:*\n`;
  items.forEach((item, i) => {
    msg += `${i + 1}. ${item.title}\n`;
    msg += `   💾 Size: ${item.size}  |  ID: ${item.id}\n`;
  });

  msg += `\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `📦 *Total Games:* ${items.reduce((s, i) => s + i.quantity, 0)}\n`;
  msg += `💾 *Total Size:* ${totalSize}\n`;
  msg += `💰 *Total Price:* ${totalPrice.toFixed(2)} ${currency}\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `_Sent via ${companyName ?? "GAMEARLY"}_`;

  return msg;
};
