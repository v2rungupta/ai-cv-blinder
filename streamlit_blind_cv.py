import streamlit as st
from io import BytesIO
import uuid
from PIL import Image, ImageDraw
import fitz  # PyMuPDF
import pytesseract
import re
from openai import OpenAI
import json
import time
from dotenv import load_dotenv
load_dotenv()

# ----------------- CONFIG -----------------
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# ----------------- PDF → Images -----------------
def pdf_to_images(pdf_bytes):
    pdf = fitz.open(stream=pdf_bytes, filetype="pdf")
    images = []
    for page in pdf:
        pix = page.get_pixmap(dpi=300)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        images.append(img)
    return images

# ----------------- OCR with char positions -----------------
def extract_ocr_data_with_positions(image):
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    ocr_data = []
    page_text = ""
    char_index = 0
    for i in range(len(data['text'])):
        text = data['text'][i].strip()
        if text:
            bbox = (data['left'][i], data['top'][i],
                    data['left'][i]+data['width'][i],
                    data['top'][i]+data['height'][i])
            char_start = char_index
            char_end = char_start + len(text)
            ocr_data.append({
                "text": text,
                "bbox": bbox,
                "char_start": char_start,
                "char_end": char_end
            })
            page_text += text + " "
            char_index = len(page_text)
    return page_text.strip(), ocr_data

# ----------------- AI text detection -----------------
def detect_sensitive_text_ai(full_text, categories):
    cat_prompt = ", ".join(categories)
    prompt = f"""
You are a resume anonymizer. From the text below, identify ONLY the requested fields:
{cat_prompt}

Return JSON ONLY, like this:
{{"blocks":[{{"type":"name","value":"John Doe"}},{{"type":"email","value":"abc@example.com"}}]}}

Text:
{full_text}
"""
    try:
        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role":"system","content":prompt}],
            temperature=0
        )
        content = response.choices[0].message.content
        match = re.search(r'(\{.*\})', content, re.DOTALL)
        if match:
            json_text = match.group(1).replace("'", '"')
            blocks = json.loads(json_text).get("blocks", [])
        else:
            blocks = []
    except Exception as e:
        st.warning(f"AI detection failed: {e}")
        blocks = []

    # Blind all links if Links category is selected
    if "Links" in categories:
        url_pattern = re.compile(r"https?://\S+", re.IGNORECASE)
        for url in url_pattern.findall(full_text):
            blocks.append({"type":"link","value":url})

    return blocks

# ----------------- Map sensitive text → OCR boxes -----------------
def find_sensitive_boxes(ocr_data, sensitive_blocks):
    boxes = []
    for block in sensitive_blocks:
        val = block['value']
        if isinstance(val, list):
            val = " ".join(val)
        val = val.strip()
        if not val:
            continue
        val_words = val.split()
        for i in range(len(ocr_data) - len(val_words) + 1):
            phrase = " ".join([ocr_data[j]['text'] for j in range(i, i+len(val_words))])
            if phrase.lower() == val.lower():
                boxes.extend([ocr_data[j]['bbox'] for j in range(i, i+len(val_words))])
    return boxes

# ----------------- Redact -----------------
def redact_image(image, boxes):
    draw = ImageDraw.Draw(image)
    for box in boxes:
        draw.rectangle(box, fill="black")
    return image

def images_to_pdf_bytes(images):
    out = BytesIO()
    images[0].save(out, format="PDF", save_all=True, append_images=images[1:])
    return out.getvalue()

# ----------------- STREAMLIT UI -----------------
# Display Atreus Global logo (replace with your file path)
st.image("logo.png", width=500)

st.title("🛡️ AI CV Blinder (Name, Email, Phone, Address, Links)")

uploads = st.file_uploader(
    "Upload one or more PDFs",
    type=["pdf"],
    accept_multiple_files=True
)

if uploads:
    st.sidebar.header("Select categories to censor:")
    censor_name = st.sidebar.checkbox("Name", False)
    censor_email = st.sidebar.checkbox("Email", True)
    censor_phone = st.sidebar.checkbox("Phone", True)
    censor_address = st.sidebar.checkbox("Address", True)
    censor_links = st.sidebar.checkbox("Links", False)  # blinds all links

    categories_to_censor = []
    if censor_name: categories_to_censor.append("Name")
    if censor_email: categories_to_censor.append("Email")
    if censor_phone: categories_to_censor.append("Phone")
    if censor_address: categories_to_censor.append("Address")
    if censor_links: categories_to_censor.append("Links")

    cv_data = []
    progress_text = st.empty()
    progress_bar = st.progress(0)
    total = len(uploads)

    # Step 1: OCR + AI detection
    for i, upload in enumerate(uploads):
        progress_text.text(f"Analyzing CV {i+1}/{total}...")
        file_bytes = upload.read()
        images = pdf_to_images(file_bytes)

        all_text = ""
        all_ocr_data = []
        for img in images:
            page_text, ocr_data = extract_ocr_data_with_positions(img)
            all_text += page_text + "\n"
            all_ocr_data.append(ocr_data)

        sensitive_blocks = detect_sensitive_text_ai(all_text, categories_to_censor)

        cv_data.append({
            "name": upload.name,
            "images": images,
            "blocks": sensitive_blocks,
            "ocr_data": all_ocr_data
        })
        progress_bar.progress((i+1)/total)
        time.sleep(0.1)

    st.success("✅ Detection complete. Press 'Blind CVs' to redact.")

    # Step 2: Manual Blinding
    if st.button("🛡️ Blind CVs"):
        for cv in cv_data:
            redacted_images = []
            for page_idx, img in enumerate(cv["images"]):
                boxes = find_sensitive_boxes(
                    cv["ocr_data"][page_idx],
                    [b for b in cv["blocks"] if b["type"].capitalize() in categories_to_censor]
                )
                redacted_images.append(redact_image(img, boxes))
            redacted_pdf = images_to_pdf_bytes(redacted_images)
            candidate_code = "CV-" + uuid.uuid4().hex[:6].upper()
            st.download_button(
                f"⬇ Download {cv['name']} (Blinded PDF)",
                data=redacted_pdf,
                file_name=f"{candidate_code}_blind.pdf",
                mime="application/pdf"
            )
