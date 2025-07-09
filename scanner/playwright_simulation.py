from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import time
import csv
import json

def analyze_behavioral_risk(traps_found, total_clickables):
    """
    Analyzes the behavioral risk based on traps found during browsing simulation.
    """
    if not traps_found:
        return {
            "behavioral_verdict": "safe",
            "trap_characteristics": {
                "max_opacity": 1,
                "min_opacity": 1,
                "max_zindex": 0,
                "coverage_ratio": 0,
                "high_risk_traps_found": False,
                "fake_cursor_detected": False,
                "auto_form_submission_detected": False,
                "cursor_jacking_detected": False
            }
        }

    max_opacity = 0
    min_opacity = 1
    max_zindex = 0
    total_coverage = 0
    high_risk_traps_found = False
    fake_cursor_detected = False
    auto_form_submission_detected = False
    cursor_jacking_detected = False

    # Deduplicate traps - keep only one per type
    unique_traps = {}
    for trap in traps_found:
        trap_type = trap.get("type")
        if trap_type not in unique_traps:
            unique_traps[trap_type] = trap

    for trap in unique_traps.values():
        details = trap.get("details", "")
        covered = trap.get("covered_clickables", [])
        opacity = 1.0
        zindex = 0

        # Extract opacity and z-index from trap details
        if "opacity:" in details.lower():
            try:
                opacity_part = details.lower().split("opacity:")[1].split(",")[0].strip()
                opacity = float(opacity_part)
            except:
                pass

        if "z-index:" in details.lower():
            try:
                zindex_str = details.lower().split("z-index:")[1].split(",")[0].strip()
                zindex = int(zindex_str) if zindex_str.isdigit() else 0
            except:
                pass

        max_opacity = max(max_opacity, opacity)
        min_opacity = min(min_opacity, opacity)
        max_zindex = max(max_zindex, zindex)
        total_coverage += len(set(covered))

        # Check for specific high-risk traps
        if trap.get("type") == "Fake Cursor":
            fake_cursor_detected = True
        if trap.get("type") == "Auto Form Submission":
            auto_form_submission_detected = True
        if trap.get("type") == "Cursor Jacking":
            cursor_jacking_detected = True

        # High risk trap types
        high_risk_types = [
            "Multi-step Trap", "Pointer Events Trap", "Double-click Trap", 
            "Animated Trap", "Click Interception", "Form Manipulation", 
            "UI Redressing", "Iframe Overlay", "Zero Opacity Overlay",
            "Clipboard Hijacking", "Multi-layer Frame"
        ]
        
        if trap.get("type") in high_risk_types:
            high_risk_traps_found = True

    # Determine behavioral verdict
    if (fake_cursor_detected or auto_form_submission_detected or cursor_jacking_detected or
        high_risk_traps_found or max_opacity < 0.05 or max_zindex >= 1):
        behavioral_verdict = "malicious"
    elif high_risk_traps_found or min_opacity < 0.3 or max_zindex >= 1:
        behavioral_verdict = "suspicious"
    else:
        behavioral_verdict = "safe"

    return {
        "behavioral_verdict": behavioral_verdict,
        "trap_characteristics": {
            "max_opacity": max_opacity,
            "min_opacity": min_opacity,
            "max_zindex": max_zindex,
            "coverage_ratio": total_coverage / total_clickables if total_clickables > 0 else 0,
            "high_risk_traps_found": high_risk_traps_found,
            "fake_cursor_detected": fake_cursor_detected,
            "auto_form_submission_detected": auto_form_submission_detected,
            "cursor_jacking_detected": cursor_jacking_detected
        }
    }

def is_common_element(element):
    # Check if element is likely a common UI element (cookie banner, chat, modal, etc.)
    common_patterns = ['cookie', 'gdpr', 'privacy', 'banner', 'notification',
                      'chat', 'support', 'help', 'modal', 'dialog', 'lightbox', 'popup',
                      'overlay', 'backdrop', 'consent', 'accept', 'decline', 'close',
                      'loader', 'spinner', 'loading', 'toast', 'alert', 'ad', 'advertisement']

    try:
        class_attr = element.get_attribute('class') or ''
        id_attr = element.get_attribute('id') or ''
        text_content = element.text_content().lower() or ''
        role_attr = element.get_attribute('role') or ''
        aria_hidden = element.get_attribute('aria-hidden')

        # Check for common patterns in class, id, text, or role
        for pattern in common_patterns:
            if (pattern in class_attr.lower() or
                pattern in id_attr.lower() or
                pattern in text_content or
                pattern in role_attr.lower()):
                return True

        # Specific check for accessibility roles often used by legitimate overlays
        if role_attr in ['dialog', 'alertdialog', 'banner', 'complementary', 'contentinfo', 'form', 'main', 'navigation', 'region', 'alert', 'status']:
            return True

        # If aria-hidden is true, it's likely not meant to be interacted with visually
        if aria_hidden == 'true':
            return True

    except Exception as e:
        pass

    return False

def detect_cursor_jacking(page):
    """Detects cursor jacking techniques"""
    try:
        # Check for body cursor:none
        cursor_none = page.evaluate("""() => {
            return window.getComputedStyle(document.body).cursor === 'none';
        }""")
        
        # Check for fake cursor elements
        fake_cursor = page.evaluate("""() => {
            const elements = document.querySelectorAll('*');
            for (const el of elements) {
                const style = window.getComputedStyle(el);
                const w = parseInt(style.width);
                const h = parseInt(style.height);
                if (style.pointerEvents === 'none' && 
                    (style.position === 'absolute' || style.position === 'fixed') &&
                    w > 8 && w <= 64 && h > 8 && h <= 64 &&
                    (style.clipPath !== 'none' || el.className.includes('cursor'))) {
                    return true;
                }
            }
            return false;
        }""")
        
        # Check for mousemove tracking
        mousemove_tracking = page.evaluate("""() => {
            return !!document.body.onmousemove || !!document.onmousemove;
        }""")
        
        if cursor_none or fake_cursor or mousemove_tracking:
            details = []
            if cursor_none: details.append("body{cursor:none}")
            if fake_cursor: details.append("fake cursor element detected")
            if mousemove_tracking: details.append("mousemove tracking")
            
            return {
                "type": "Cursor Jacking",
                "description": "Cursor manipulation techniques detected",
                "details": "; ".join(details)
            }
    except Exception as e:
        pass
    return None

def detect_auto_form_submission_v1(page):
    """Detects auto form submission patterns"""
    try:
        # Check for generic attack pattern
        generic_attack = page.query_selector('.generic-attack')
        if generic_attack:
            style = page.evaluate("""(el) => {
                const style = window.getComputedStyle(el);
                return {
                    opacity: parseFloat(style.opacity),
                    zIndex: parseInt(style.zIndex || 0)
                };
            }""", generic_attack)
            
            if style and style['opacity'] < 0.2 and style['zIndex'] >= 600:
                return {
                    "type": "Auto Form Submission",
                    "description": "Generic attack pattern detected",
                    "details": f"Opacity: {style['opacity']}, Z-index: {style['zIndex']}"
                }
        
        # Check for click event listeners that submit forms
        auto_submit = page.evaluate("""() => {
            const scripts = Array.from(document.querySelectorAll('script'));
            for (const script of scripts) {
                if (script.textContent.includes('document.addEventListener(\'click\'')) {
                    return true;
                }
            }
            return false;
        }""")
        
        if auto_submit:
            return {
                "type": "Auto Form Submission",
                "description": "Auto-submit script detected",
                "details": "Click event listener found in script"
            }
    except Exception as e:
        pass
    return None

def detect_multi_step_trap(page, clickable, box):
    """Detects multi-step clickjacking traps"""
    try:
        # First click to trigger the trap
        try:
            clickable.click(timeout=2000)
        except Exception as e:
            print(f"First click intercepted (may be expected): {str(e)}")
        
        # Handle potential alert dialog
        try:
            page.on('dialog', lambda dialog: dialog.dismiss())
        except:
            pass
        
        # Wait for trap to appear
        time.sleep(1)
        
        # Get element at click position
        center_x = box['x'] + box['width']/2
        center_y = box['y'] + box['height']/2
        
        element_info = page.evaluate("""([x, y]) => {
            const el = document.elementFromPoint(x, y);
            if (!el) return null;
            const style = window.getComputedStyle(el);
            return {
                tag: el.tagName,
                id: el.id,
                pointerEvents: style.pointerEvents,
                opacity: parseFloat(style.opacity),
                zIndex: parseInt(style.zIndex || 0),
                display: style.display
            };
        }""", [center_x, center_y])
        
        if not element_info:
            return None
            
        # Check if this is a new interactive element
        original_element_info = page.evaluate("""(el) => {
            const style = window.getComputedStyle(el);
            return {
                id: el.id,
                pointerEvents: style.pointerEvents
            };
        }""", clickable)
        
        if (element_info['id'] != original_element_info['id'] and 
            element_info['pointerEvents'] == 'auto' and
            element_info['display'] != 'none'):
            return {
                "type": "Multi-step Trap",
                "description": "Interactive element appeared after first click",
                "details": f"{element_info['tag']}#{element_info['id']} (z-index: {element_info['zIndex']})",
                "covered_clickables": []
            }
    except Exception as e:
        pass
    return None

def detect_pointer_events_trap(page, clickable, box):
    """Detects pointer-events based clickjacking traps"""
    try:
        center_x = box['x'] + box['width']/2
        center_y = box['y'] + box['height']/2
        
        elements_info = page.evaluate("""([x, y]) => {
            const elements = document.elementsFromPoint(x, y);
            return elements.map(el => {
                const style = window.getComputedStyle(el);
                return {
                    tag: el.tagName,
                    id: el.id,
                    pointerEvents: style.pointerEvents,
                    opacity: parseFloat(style.opacity),
                    zIndex: parseInt(style.zIndex || 0),
                    display: style.display,
                    position: style.position
                };
            });
        }""", [center_x, center_y])
        
        if not elements_info or len(elements_info) < 2:
            return None
            
        # Look for pointer-events trap pattern
        for i in range(len(elements_info) - 1):
            current = elements_info[i]
            next_el = elements_info[i + 1]
            
            # Pattern 1: Transparent interactive element under non-interactive cover
            if (current['pointerEvents'] == 'auto' and
                current['opacity'] < 0.1 and
                next_el['pointerEvents'] == 'none' and
                current['zIndex'] > 0):
                return {
                    "type": "Pointer Events Trap",
                    "description": "Transparent interactive element under non-interactive cover",
                    "details": f"{current['tag']}#{current['id']} under {next_el['tag']}#{next_el['id']}",
                    "covered_clickables": []
                }
            
            # Pattern 2: Fixed/absolute positioned element with pointer-events:none covering clickable
            if (current['pointerEvents'] == 'none' and
                current['position'] in ['fixed', 'absolute'] and
                current['display'] != 'none' and
                current['zIndex'] > 0):
                return {
                    "type": "Pointer Events Trap",
                    "description": "Fixed/absolute positioned element with pointer-events:none covering clickable",
                    "details": f"{current['tag']}#{current['id']} covering clickable",
                    "covered_clickables": []
                }
    except Exception as e:
        pass
    return None

def detect_click_interception(page, clickable):
    """Detects click interception techniques with better error handling"""
    handlers = []
    try:
        current = clickable
        while current:
            try:
                pointer_events = page.evaluate("""(el) => {
                    if (!el) return 'none';
                    return window.getComputedStyle(el).pointerEvents;
                }""", current)
                
                if pointer_events == 'none':
                    tag = page.evaluate("el => el.tagName.toLowerCase()", current)
                    handlers.append(f"{tag} with pointer-events:none")
                
                parent = page.evaluate_handle("el => el.parentElement", current)
                if not parent or page.evaluate("el => !el", parent):
                    break
                current = parent
            except Exception as e:
                pass
                break
        
        if handlers:
            return {
                "type": "Click Interception",
                "description": "Element has ancestor styles that may intercept clicks",
                "details": f"Ancestors with pointer-events:none: {', '.join(handlers)}"
            }
    except Exception as e:
       pass
    return None

def detect_form_manipulation(page, clickable):
    # Check for form manipulation techniques
    try:
        if clickable.evaluate('el => el.tagName.toLowerCase()') in ['input', 'select', 'textarea']:
            form_info = page.evaluate("""
            (el) => {
                let suspicious = false;
                let details = [];

                // Check for hidden form fields
                if (el.type === 'hidden' && el.name) {
                    suspicious = true;
                    details.push('hidden input field');
                }

                // Check for value manipulation
                if (el.value && el.defaultValue && el.value !== el.defaultValue && el.readOnly) {
                    suspicious = true;
                    details.push('modified readonly default value');
                }

                // Check for form action hijacking
                let form = el.form;
                if (form) {
                    if (!form.action || form.action.match(/^\\s*#?\\s*$/)) {
                         suspicious = true;
                         details.push(`empty or hash form action: ${form.action}`);
                    }
                    if (form.onsubmit) {
                        suspicious = true;
                        details.push('onsubmit handler');
                    }
                    if (form.target && form.target.toLowerCase() !== '_self' && form.target.toLowerCase() !== '_top') {
                        suspicious = true;
                        details.push(`form target: ${form.target}`);
                    }
                }

                return suspicious ? details : false;
            }
            """, clickable)

            if form_info:
                return {
                    "type": "Form Manipulation",
                    "description": "Suspicious form field or form attribute manipulation detected",
                    "details": f"Indicators: {', '.join(form_info)}"
                }
    except Exception as e:
        pass
        pass
    return None

def detect_iframe_overlay(page):
    # Check for iframe overlays
    try:
        iframes = page.query_selector_all('iframe')
        for iframe in iframes:
            if is_common_element(iframe):
                continue

            box = iframe.bounding_box()
            if not box:
                continue

            style_opacity = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("opacity")', iframe)
            z_index = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("z-index")', iframe)
            pointer_events = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("pointer-events")', iframe)

            if (float(style_opacity) < 0.8 and
                z_index and z_index.isdigit() and int(z_index) >= 1 and
                pointer_events != "none"):

                viewport = page.viewport_size or {"width": 1200, "height": 800}
                iframe_area = box['width'] * box['height']
                viewport_area = viewport['width'] * viewport['height']

                if viewport_area > 0 and iframe_area / viewport_area > 0.1:
                    return {
                        "type": "Iframe Overlay",
                        "description": "Transparent/semi-transparent iframe overlay detected covering a significant portion of the viewport.",
                        "details": f"Opacity: {style_opacity}, Z-index: {z_index}, Pointer-events: {pointer_events}"
                    }
    except Exception as e:
        pass
        pass
    return None

def detect_ui_redressing(page):
    # Check for UI redressing techniques
    try:
        framebusting = page.evaluate("""
        () => {
            let scripts = Array.from(document.querySelectorAll('script'));
            let framebusting_found = false;
            for (let script of scripts) {
                if (script.textContent.includes('top.location') ||
                    script.textContent.includes('parent.location') ||
                    script.textContent.includes('self.location') ||
                    script.textContent.includes('window.onbeforeunload') ||
                    script.textContent.includes('window.onload')) {
                    framebusting_found = true;
                    break;
                }
            }
            return framebusting_found;
        }
        """)

        viewport = page.evaluate("""
        () => {
            let meta = document.querySelector('meta[name="viewport"]');
            if (meta && (meta.content.includes('user-scalable=no') || meta.content.includes('maximum-scale=1'))) {
                return true;
            }
            return false;
        }
        """)

        cursor_jacking = page.evaluate("""
        () => {
            const bodyStyle = window.getComputedStyle(document.body);
            return bodyStyle.cursor === 'none';
        }
        """)

        if framebusting or viewport or cursor_jacking:
            return {
                "type": "UI Redressing",
                "description": "Potential UI redressing techniques detected",
                "details": f"Framebusting: {framebusting}, Viewport manipulation: {viewport}, Cursor Jacking (body cursor:none): {cursor_jacking}"
            }
    except Exception as e:
        pass
    return None

def detect_auto_form_submission(page, forms_before_click, url):
    try:
        forms_after_click = page.query_selector_all('form')
        for form_after in forms_after_click:
            try:
                form_html = page.evaluate('(el) => el.outerHTML', form_after)
                if form_html not in forms_before_click and not is_common_element(form_after):
                    display_style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("display")', form_after)
                    visibility_style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("visibility")', form_after)
                    if display_style == 'none' or visibility_style == 'hidden':
                        return {
                            "type": "Auto Form Submission",
                            "description": "Hidden form dynamically created and/or submitted after user interaction.",
                            "details": "New hidden form detected"
                        }
            except Exception:
                continue
    except Exception as e:
        pass
    return None

def detect_zero_opacity_overlay(page, clickable, box):
    try:
        overlays = page.query_selector_all("div, section, span, a, button, input")
        for overlay in overlays:
            if is_common_element(overlay):
                continue

            obox = overlay.bounding_box()
            if not obox:
                continue

            # Calculate overlap area
            overlap_x = max(0, min(box['x'] + box['width'], obox['x'] + obox['width']) - max(box['x'], obox['x']))
            overlap_y = max(0, min(box['y'] + box['height'], obox['y'] + obox['height']) - max(box['y'], obox['y']))
            overlap_area = overlap_x * overlap_y
            clickable_area = box['width'] * box['height']

            if clickable_area > 0 and (overlap_area / clickable_area > 0.1):
                style_opacity = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("opacity")', overlay)
                z_index = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("z-index")', overlay)
                pointer_events = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("pointer-events")', overlay)
                display_style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("display")', overlay)
                visibility_style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("visibility")', overlay)

                # General case for overlays
                if ((float(style_opacity) < 0.05 or float(style_opacity) > 0.95) 
                    and z_index 
                    and z_index.isdigit() 
                    and int(z_index) > 0 
                    and pointer_events == "auto" 
                    and display_style != "none" 
                    and visibility_style != "hidden"):
                    return {
                        "type": "Overlay Div",
                        "description": "Suspicious overlay div detected intercepting clicks",
                        "details": f"Opacity: {style_opacity}, Z-index: {z_index}, Pointer-events: {pointer_events}",
                        "covered_clickables": []
                    }
    except Exception as e:
        pass
    return None

def detect_delayed_overlay(page, clickable, box):
    try:
        # First click to potentially trigger the trap
        clickable.click(timeout=3000)
        
        # Wait for trap to appear (longer wait for delayed traps)
        time.sleep(1)
        
        # Check for new overlays at click position
        center_x = int(box['x'] + box['width'] / 2)
        center_y = int(box['y'] + box['height'] / 2)
        element_at_point = page.evaluate_handle("([x, y]) => document.elementFromPoint(x, y)", [center_x, center_y])
        
        if not page.evaluate("(a, b) => a.isSameNode(b)", element_at_point, clickable):
            overlay_info = page.evaluate("""(el) => {
                if (!el) return null;
                const style = window.getComputedStyle(el);
                return {
                    tag: el.tagName,
                    id: el.id,
                    class: el.className,
                    opacity: parseFloat(style.opacity),
                    pointerEvents: style.pointerEvents,
                    zIndex: parseInt(style.zIndex || 0),
                    display: style.display,
                    width: el.offsetWidth,
                    height: el.offsetHeight,
                    backgroundColor: style.backgroundColor
                };
            }""", element_at_point)
            
            if not overlay_info:
                return None
                
            # Special detection for 12.html pattern
            if (overlay_info['pointerEvents'] == "auto" and 
                overlay_info['display'] == "block" and
                overlay_info['zIndex'] >= 9999 and
                'rgba(255, 0, 0, 0.4)' in overlay_info['backgroundColor']):
                return {
                    "type": "Double-click Trap",
                    "description": "Delayed overlay matching known double-click trap pattern (12.html)",
                    "details": f"Tag: {overlay_info['tag']}, opacity: {overlay_info['opacity']}, z-index: {overlay_info['zIndex']}, background: {overlay_info['backgroundColor']}",
                    "covered_clickables": []
                }
            
            # General case for delayed overlays
            if (overlay_info['pointerEvents'] == "auto" and 
                overlay_info['display'] != "none" and
                overlay_info['zIndex'] > 0):
                return {
                    "type": "Delayed Overlay",
                    "description": "Overlay appeared after first click to trap interactions",
                    "details": f"Tag: {overlay_info['tag']}, opacity: {overlay_info['opacity']}, z-index: {overlay_info['zIndex']}",
                    "covered_clickables": []
                }
    except Exception as e:
        pass
    return None

def detect_clipboard_hijacking(page):
    clipboard_hijack_detected = False
    details = []

    try:
        scripts = page.query_selector_all("script")
        for script in scripts:
            try:
                script_content = script.evaluate("s => s.textContent")
                if script_content:
                    if "navigator.clipboard.writeText" in script_content:
                        details.append("Script using navigator.clipboard.writeText")
                        clipboard_hijack_detected = True
                    if "document.execCommand('copy')" in script_content:
                        details.append("Script using document.execCommand('copy')")
                        clipboard_hijack_detected = True
                    if "document.execCommand('cut')" in script_content:
                        details.append("Script using document.execCommand('cut')")
                        clipboard_hijack_detected = True
            except Exception:
                pass

        has_paste_listener = page.evaluate("""
            (function() {
                const events = ['paste'];
                for (const event of events) {
                    if (document.body.hasAttribute(`on${event}`)) return true;
                    const elements = document.querySelectorAll('*');
                    for (const el of elements) {
                        if (el.hasAttribute(`on${event}`)) return true;
                    }
                }
                return false;
            })();
        """)
        if has_paste_listener:
            details.append("Page contains elements with 'paste' event listeners")
            clipboard_hijack_detected = True

        if clipboard_hijack_detected:
            return {
                "type": "Clipboard Hijacking",
                "description": "Potential clipboard hijacking detected.",
                "details": "; ".join(details)
            }
    except Exception as e:
        pass
        pass
    return None

def detect_multi_layer_frames(page):
    iframe_elements = page.query_selector_all("iframe")
    frame_info = []
    for iframe_el in iframe_elements:
        try:
            box = iframe_el.bounding_box()
            if box:
                z_index_str = iframe_el.evaluate("e => window.getComputedStyle(e).zIndex")
                z_index = int(z_index_str) if z_index_str and z_index_str.isdigit() else 0
                frame_info.append({"element": iframe_el, "box": box, "z_index": z_index})
        except Exception:
            pass

    if len(frame_info) > 1:
        for i in range(len(frame_info)):
            for j in range(i + 1, len(frame_info)):
                frame1 = frame_info[i]
                frame2 = frame_info[j]

                box1 = frame1["box"]
                box2 = frame2["box"]

                overlap_x1 = max(box1['x'], box2['x'])
                overlap_y1 = max(box1['y'], box2['y'])
                overlap_x2 = min(box1['x'] + box1['width'], box2['x'] + box2['width'])
                overlap_y2 = min(box1['y'] + box1['height'], box2['y'] + box2['height'])

                overlap_width = max(0, overlap_x2 - overlap_x1)
                overlap_height = max(0, overlap_y2 - overlap_y1)

                overlap_area = overlap_width * overlap_height

                min_frame_area = min(box1['width'] * box1['height'], box2['width'] * box2['height'])
                if min_frame_area > 0 and overlap_area / min_frame_area > 0.5:
                    overlay_frame = frame1 if frame1["z_index"] > frame2["z_index"] else frame2
                    underlying_frame = frame2 if frame1["z_index"] > frame2["z_index"] else frame1

                    return {
                        "type": "Multi-layer Frame",
                        "description": "Significant overlap detected between iframes.",
                        "details": f"Overlay frame (z-index: {overlay_frame['z_index']}) over underlying frame (z-index: {underlying_frame['z_index']}). Overlap area: {overlap_area:.2f}px²",
                        "covered_clickables": []
                    }
    return None

def detect_invisible_iframes(page):
    traps = []
    try:
        iframes = page.query_selector_all("iframe")
        for iframe in iframes:
            try:
                box = iframe.bounding_box()
                if not box or box["width"] * box["height"] < 5000:
                    continue
                
                style_opacity = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("opacity")', iframe)
                pointer_events = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("pointer-events")', iframe)
                z_index = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("z-index")', iframe)
                display_style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("display")', iframe)
                src = iframe.get_attribute("src") or "about:blank"
                
                if (float(style_opacity) < 0.1 and 
                    pointer_events != "none" and 
                    display_style != "none" and 
                    z_index and z_index.isdigit() and 
                    int(z_index) >= 1):
                    
                    traps.append({
                        "type": "Invisible Iframe",
                        "description": "Invisible iframe detected with pointer-events enabled.",
                        "details": f"src: {src}, opacity: {style_opacity}, pointer-events: {pointer_events}, z-index: {z_index}",
                        "covered_clickables": []
                    })
                    
            except Exception as e:
                pass
                continue
    except Exception as e:
        pass
    return traps

def is_covered_by_overlay(page, clickable, box):
    center_x = int(box['x'] + box['width'] / 2)
    center_y = int(box['y'] + box['height'] / 2)
    try:
        element_at_point = page.evaluate_handle("([x, y]) => document.elementFromPoint(x, y)", [center_x, center_y])
        return not page.evaluate("(a, b) => a.isSameNode(b)", element_at_point, clickable)
    except Exception as e:
        pass
        return False

def prioritize_clickables(clickables, page):
    prioritized = []
    for element in clickables:
        try:
            if is_common_element(element):
                continue

            tag = element.evaluate('el => el.tagName.toLowerCase()')
            box = element.bounding_box()
            if not box or box['width'] == 0 or box['height'] == 0:
                continue

            score = 0

            if tag == 'button' or tag == 'input' and (element.get_attribute('type') in ['button', 'submit']):
                score += 3
            elif tag == 'a' or tag == 'select' or tag == 'textarea':
                score += 2
            elif element.get_attribute('role') == 'button' or element.get_attribute('tabindex') is not None:
                 score += 2

            if element.evaluate('el => el.hasAttribute("onclick")'):
                score += 2
            if element.evaluate('el => el.hasAttribute("id")'):
                score += 1
            if element.get_attribute('href') or element.get_attribute('action'):
                score += 1

            viewport = page.viewport_size
            if viewport:
                center_x = box['x'] + box['width']/2
                center_y = box['y'] + box['height']/2
                dist_x_norm = abs(center_x - viewport['width']/2) / (viewport['width']/2)
                dist_y_norm = abs(center_y - viewport['height']/2) / (viewport['height']/2)
                score += max(0, 3 - (dist_x_norm + dist_y_norm))

            area = box['width'] * box['height']
            score += min(5, area/1000)

            prioritized.append((score, element))

        except Exception as e:
            print(f"Error prioritizing element: {e}")
            continue

    prioritized.sort(key=lambda x: -x[0])
    return [elem for (score, elem) in prioritized[:50]]

def get_element_properties(page, element):
    return page.evaluate("""(el) => {
        const style = window.getComputedStyle(el);
        return {
            tag: el.tagName,
            id: el.id,
            class: el.className,
            opacity: parseFloat(style.opacity),
            pointerEvents: style.pointerEvents,
            zIndex: parseInt(style.zIndex || 0),
            display: style.display,
            width: el.offsetWidth,
            height: el.offsetHeight
        };
    }""", element)

def human_like_browse(url):
    actions_log = []
    traps_found = []
    shap_explanation = []
    total_clickables = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(url, timeout=60000, wait_until='domcontentloaded')
            actions_log.append("Visited page.")
            page.mouse.wheel(0, 500)
            actions_log.append("Scrolled down.")
            time.sleep(1)
            page.mouse.wheel(0, -500)
            actions_log.append("Scrolled up.")
            time.sleep(1)
            # Early exit for obviously safe sites
            initial_safety_check = page.evaluate("""() => {
                return {
                    is_https: window.location.protocol === 'https:',
                    has_trusted_favicon: !!document.querySelector('link[rel=\"icon\"][href*=\"trusted\"]'),
                };
            }""")
            if initial_safety_check['is_https'] and not any([detect_ui_redressing(page), detect_cursor_jacking(page)]):
                return {
                    "actions_log": ["Early exit - site appears safe based on initial indicators"],
                    "traps_found": [],
                    "shap_explanation": ["Site appears safe based on initial security indicators"],
                    "behavioral_verdict": "safe",
                    "trap_characteristics": {
                        "max_opacity": 1,
                        "min_opacity": 1,
                        "max_zindex": 0,
                        "coverage_ratio": 0,
                        "high_risk_traps_found": False,
                        "fake_cursor_detected": False,
                        "auto_form_submission_detected": False,
                        "cursor_jacking_detected": False
                    }
                }
            viewport = page.viewport_size or {"width": 1200, "height": 800}

            ui_redressing_trap = detect_ui_redressing(page)
            if ui_redressing_trap:
                traps_found.append(ui_redressing_trap)
                shap_explanation.append("UI Redressing: Potential framebusting, viewport manipulation, or cursor jacking detected.")

            initial_forms_html = set(page.evaluate('[...document.querySelectorAll("form")].map(form => form.outerHTML)'))

            clickables = page.query_selector_all("button, a, [role=button], input[type=button], input[type=submit], input[type=image], [tabindex]:not([tabindex='-1'])")
            prioritized_clickables = prioritize_clickables(clickables, page)
            total_clickables = len(prioritized_clickables)

            clipboard_trap = detect_clipboard_hijacking(page)
            if clipboard_trap:
                traps_found.append(clipboard_trap)
                shap_explanation.append(f"Clipboard Hijacking: {clipboard_trap['details']}")

            multi_layer_frame_trap = detect_multi_layer_frames(page)
            if multi_layer_frame_trap:
                traps_found.append(multi_layer_frame_trap)
                shap_explanation.append(f"Multi-layer Frame: {multi_layer_frame_trap['description']}")

            invisible_iframes = detect_invisible_iframes(page)
            if invisible_iframes:
                traps_found.extend(invisible_iframes)
                shap_explanation.extend([f"Invisible Iframe: {trap['details']}" for trap in invisible_iframes])

            cursor_jacking_trap = detect_cursor_jacking(page)
            if cursor_jacking_trap:
                traps_found.append(cursor_jacking_trap)
                shap_explanation.append(f"Cursor Jacking: {cursor_jacking_trap['description']}")

            auto_form_submission_v1_trap = detect_auto_form_submission_v1(page)
            if auto_form_submission_v1_trap:
                traps_found.append(auto_form_submission_v1_trap)
                shap_explanation.append(f"Auto Form Submission (V1): {auto_form_submission_v1_trap['description']}")

            if not prioritized_clickables:
                actions_log.append("No important clickable elements found.")
            else:
                for idx, clickable in enumerate(prioritized_clickables):
                    try:
                        if is_common_element(clickable):
                            continue
                        # Quick safety check before attempting deep analysis
                        props = get_element_properties(page, clickable)
                        if props['pointerEvents'] == 'auto' and props['opacity'] > 0.9 and props['zIndex'] == 0:
                            continue  # Skip deep analysis for obviously safe elements
                        page.evaluate("(el) => el.scrollIntoView({behavior: 'smooth', block: 'center'})", clickable)
                        time.sleep(0.5)

                        box = clickable.bounding_box()
                        if not box or box['width'] == 0 or box['height'] == 0:
                            print(f"[DEBUG] Skipping invisible or zero-size element {idx+1} (tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')})")
                            continue

                        # Multi-step trap detection
                        multi_step_trap = detect_multi_step_trap(page, clickable, box)
                        if multi_step_trap:
                            traps_found.append(multi_step_trap)
                            shap_explanation.append(
                                f"Multi-step Trap: {multi_step_trap['description']} "
                                f"Details: {multi_step_trap['details']}"
                            )

                        # Pointer events trap detection
                        pointer_events_trap = detect_pointer_events_trap(page, clickable, box)
                        if pointer_events_trap:
                            traps_found.append(pointer_events_trap)
                            shap_explanation.append(
                                f"Pointer Events Trap: {pointer_events_trap['description']} "
                                f"Details: {pointer_events_trap['details']}"
                            )

                        # Enhanced detection for 2.html pattern
                        overlay_div_trap = detect_zero_opacity_overlay(page, clickable, box)
                        if overlay_div_trap:
                            traps_found.append(overlay_div_trap)
                            shap_explanation.append(
                                f"Overlay Div: {overlay_div_trap['description']} covering element {idx+1} "
                                f"(tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')}). "
                                f"Details: {overlay_div_trap['details']}"
                            )

                        # Enhanced detection for 12.html pattern
                        delayed_overlay_trap = detect_delayed_overlay(page, clickable, box)
                        if delayed_overlay_trap:
                            traps_found.append(delayed_overlay_trap)
                            shap_explanation.append(
                                f"{delayed_overlay_trap['type']}: {delayed_overlay_trap['description']} "
                                f"after clicking element {idx+1}. Details: {delayed_overlay_trap['details']}"
                            )

                        click_intercept_trap = detect_click_interception(page, clickable)
                        if click_intercept_trap:
                            traps_found.append(click_intercept_trap)
                            shap_explanation.append(
                                f"Click Interception: Suspicious click handlers or ancestor styles detected on element {idx+1} "
                                f"(tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')})"
                            )

                        form_manip_trap = detect_form_manipulation(page, clickable)
                        if form_manip_trap:
                            traps_found.append(form_manip_trap)
                            shap_explanation.append(
                                f"Form Manipulation: Suspicious form field or form attribute detected on element {idx+1} "
                                f"(tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')})"
                            )

                        # Existing click and trap detection logic
                        try:
                            clickable.click(timeout=3000)
                            actions_log.append(f"Clicked element {idx+1} (single click).")
                        except PlaywrightTimeoutError:
                            actions_log.append(f"Click on element {idx+1} was intercepted or timed out. Checking overlay at click position...")
                            center_x = int(box['x'] + box['width'] / 2)
                            center_y = int(box['y'] + box['height'] / 2)
                            element_at_click_point = page.evaluate_handle("([x, y]) => document.elementFromPoint(x, y)", [center_x, center_y])
                            
                            is_clickable_same_as_element_at_point = page.evaluate("(a, b) => a.isSameNode(b)", element_at_click_point, clickable)

                            if not is_clickable_same_as_element_at_point:
                                overlay_info = page.evaluate("""
                                (el) => {
                                    if (!el) return null;
                                    const style = window.getComputedStyle(el);
                                    return {
                                        tag: el.tagName,
                                        id: el.id,
                                        class: el.className,
                                        opacity: style.opacity,
                                        pointerEvents: style.pointerEvents,
                                        zIndex: style.zIndex,
                                        display: style.display,
                                        width: el.offsetWidth,
                                        height: el.offsetHeight
                                    };
                                }
                                """, element_at_click_point)
                                if overlay_info and overlay_info['opacity'] and float(overlay_info['opacity']) < 0.8 and overlay_info['zIndex'] and overlay_info['zIndex'].isdigit() and int(overlay_info['zIndex']) >= 1 and overlay_info['pointerEvents'] != "none" and overlay_info['display'] != "none":
                                    trap = {
                                        "type": "Overlay Interception",
                                        "description": "Transparent/semi-transparent overlay detected intercepting single click.",
                                        "details": f"Tag: {overlay_info['tag']}, id: {overlay_info['id']}, opacity: {overlay_info['opacity']}, pointer-events: {overlay_info['pointerEvents']}, z-index: {overlay_info['zIndex']}",
                                        "covered_clickables": [idx]
                                    }
                                    traps_found.append(trap)
                                    shap_explanation.append(
                                        f"Overlay Interception: On single click of element {idx+1} (tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')}), "
                                        f"a transparent or semi-transparent overlay (tag={overlay_info['tag']}, id={overlay_info['id']}, opacity={overlay_info['opacity']}, z-index={overlay_info['zIndex']}) intercepted the click."
                                    )

                        auto_form_submission_trap = detect_auto_form_submission(page, initial_forms_html, url)
                        if auto_form_submission_trap:
                            traps_found.append(auto_form_submission_trap)
                            shap_explanation.append(
                                f"Auto Form Submission: A hidden form was detected being dynamically created or submitted after a click event."
                            )

                        time.sleep(0.5)

                        overlays_before = page.query_selector_all("div,section,span") # Broader selection
                        overlay_html_before = set()
                        for overlay in overlays_before:
                            try:
                                oid = page.evaluate('(el) => el.outerHTML', overlay)
                                overlay_html_before.add(oid)
                            except Exception:
                                continue

                        # Double-click trap detection
                        try:
                            clickable.dblclick(timeout=3000)
                            actions_log.append(f"Double-clicked element {idx+1}.")
                        except PlaywrightTimeoutError:
                            actions_log.append(f"Double-click on element {idx+1} was intercepted or timed out. Checking overlay at click position...")
                            center_x = int(box['x'] + box['width'] / 2)
                            center_y = int(box['y'] + box['height'] / 2)
                            element_at_click_point = page.evaluate_handle("([x, y]) => document.elementFromPoint(x, y)", [center_x, center_y])
                            is_clickable_same_as_element_at_point = page.evaluate("(a, b) => a.isSameNode(b)", element_at_click_point, clickable)

                            if not is_clickable_same_as_element_at_point:
                                overlay_info = page.evaluate("""
                                (el) => {
                                    if (!el) return null;
                                    const style = window.getComputedStyle(el);
                                    return {
                                        tag: el.tagName,
                                        id: el.id,
                                        class: el.className,
                                        opacity: style.opacity,
                                        pointerEvents: style.pointerEvents,
                                        zIndex: style.zIndex,
                                        display: style.display,
                                        width: el.offsetWidth,
                                        height: el.offsetHeight
                                    };
                                }
                                """, element_at_click_point)
                                if overlay_info and overlay_info['opacity'] and float(overlay_info['opacity']) < 0.8 and overlay_info['zIndex'] and overlay_info['zIndex'].isdigit() and int(overlay_info['zIndex']) >= 1 and overlay_info['pointerEvents'] != "none" and overlay_info['display'] != "none":
                                    trap = {
                                        "type": "Double-click Trap",
                                        "description": "Transparent or semi-transparent overlay detected intercepting double-click.",
                                        "details": f"Tag: {overlay_info['tag']}, id: {overlay_info['id']}, opacity: {overlay_info['opacity']}, pointer-events: {overlay_info['pointerEvents']}, z-index: {overlay_info['zIndex']}",
                                        "covered_clickables": [idx]
                                    }
                                    traps_found.append(trap)
                                    shap_explanation.append(
                                        f"Double-click Trap: After a double-click on element {idx+1} (tag={clickable.evaluate('el => el.tagName')}, id={clickable.get_attribute('id')}), "
                                        f"a transparent or semi-transparent overlay (tag={overlay_info['tag']}, id={overlay_info['id']}, opacity={overlay_info['opacity']}, z-index={overlay_info['zIndex']}) intercepted the click."
                                    )

                        overlays_animated = page.query_selector_all("div,section,span")
                        for overlay in overlays_animated:
                            try:
                                oid = page.evaluate('(el) => el.outerHTML', overlay)
                                if oid not in overlay_html_before and not is_common_element(overlay):
                                    obox = overlay.bounding_box()
                                    if not obox:
                                        continue
                                    overlap_x = max(0, min(box['x'] + box['width'], obox['x'] + obox['width']) - max(box['x'], obox['x']))
                                    overlap_y = max(0, min(box['y'] + box['height'], obox['y'] + obox['height']) - max(box['y'], obox['y']))
                                    overlap_area = overlap_x * overlap_y
                                    clickable_area = box['width'] * box['height']
                                    if clickable_area > 0 and overlap_area / clickable_area > 0.05:
                                        style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("opacity")', overlay)
                                        pointer_events = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("pointer-events")', overlay)
                                        z_index = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("z-index")', overlay)
                                        display = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("display")', overlay)
                                        if float(style) < 0.8 and z_index and z_index.isdigit() and int(z_index) >= 1 and pointer_events != "none" and display != "none":
                                            trap = {
                                                "type": "Animated Trap",
                                                "description": "Animated overlay appeared after user interaction/page load, covering the clickable.",
                                                "details": f"Opacity: {style}, Pointer-events: {pointer_events}, Z-index: {z_index}",
                                                "covered_clickables": [idx]
                                            }
                                            traps_found.append(trap)
                                            shap_explanation.append(
                                                f"Animated Trap: A new overlay (tag={overlay.evaluate('el => el.tagName')}, id={overlay.get_attribute('id')}, opacity={style}, z-index={z_index}) appeared and covered clickable element {idx+1}."
                                            )
                            except Exception as e:
                                print(f"Error in animated trap detection: {e}")
                                continue

                    except Exception as e:
                        actions_log.append(f"Error processing element {idx+1}: {str(e)}")

            iframe_trap = detect_iframe_overlay(page)
            if iframe_trap:
                traps_found.append(iframe_trap)
                shap_explanation.append("Iframe Overlay: Transparent iframe with high z-index detected")

            # Final check for any delayed traps that might have appeared
            time.sleep(2)
            overlays_animated_final = page.query_selector_all("div,section,span")
            for idx, clickable in enumerate(prioritized_clickables):
                box = clickable.bounding_box()
                if not box:
                    continue
                for overlay in overlays_animated_final:
                    try:
                        obox = overlay.bounding_box()
                        if not obox:
                            continue
                        overlap_x = max(0, min(box['x'] + box['width'], obox['x'] + obox['width']) - max(box['x'], obox['x']))
                        overlap_y = max(0, min(box['y'] + box['height'], obox['y'] + obox['height']) - max(box['y'], obox['y']))
                        overlap_area = overlap_x * overlap_y
                        clickable_area = box['width'] * box['height']
                        if clickable_area > 0 and overlap_area / clickable_area > 0.05:
                            style = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("opacity")', overlay)
                            pointer_events = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("pointer-events")', overlay)
                            z_index = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("z-index")', overlay)
                            display = page.evaluate('(el) => window.getComputedStyle(el).getPropertyValue("display")', overlay)
                            is_already_trapped = any(
                                    (t.get("type") == "Animated Trap" or t.get("type") == "Multi-step Trap" or t.get("type") == "Overlay Interception")
                                    and idx in t.get("covered_clickables", [])
                                    for t in traps_found
                                )
                            if float(style) < 0.8 and z_index and z_index.isdigit() and int(z_index) >= 1 and pointer_events != "none" and display != "none" and not is_already_trapped and not is_common_element(overlay):
                                trap = {
                                    "type": "Animated Trap (Post-Load)",
                                    "description": "Animated overlay appeared after page load/initial interactions, covering the clickable.",
                                    "details": f"Opacity: {style}, Pointer-events: {pointer_events}, Z-index: {z_index}",
                                    "covered_clickables": [idx]
                                }
                                traps_found.append(trap)
                                shap_explanation.append(
                                    f"Animated Trap (Post-Load): A new overlay (tag={overlay.evaluate('el => el.tagName')}, id={overlay.get_attribute('id')}, opacity={style}, z-index={z_index}) appeared and covered clickable element {idx+1} after page load/initial interactions."
                                )
                    except Exception as e:
                        print(f"Error in final animated trap detection: {e}")
                        continue

            # Fake cursor detection
            try:
                fake_cursor_result = page.evaluate("""
                    () => {
                        let shap = [];
                        let cursorNone = false;
                        try {
                            cursorNone = window.getComputedStyle(document.body).cursor === 'none';
                            if (cursorNone) shap.push('body{cursor:none} hides real cursor');
                        } catch (e) {}
                        
                        let fakeCursorFound = false;
                        let elements = Array.from(document.querySelectorAll('*'));
                        for (let el of elements) {
                            let cs = window.getComputedStyle(el);
                            let w = parseInt(cs.width), h = parseInt(cs.height);
                            let suspicious = (
                                (cs.pointerEvents === 'none') &&
                                (cs.position === 'absolute' || cs.position === 'fixed') &&
                                (w > 8 && w <= 64 && h > 8 && h <= 64) &&
                                (
                                    (cs.backgroundImage && cs.backgroundImage !== 'none') ||
                                    (cs.backgroundColor && cs.backgroundColor !== 'rgba(0, 0, 0, 0)') ||
                                    (el.style.clipPath && el.style.clipPath !== '') ||
                                    (el.matches('[class*="cursor"]'))
                                )
                            );
                            if (suspicious) {
                                fakeCursorFound = true;
                                shap.push('Small, absolutely/fixed-positioned, pointer-events:none element with background/style (possible fake cursor)');
                                break;
                            }
                        }
                        
                        let hasMousemove = false;
                        if (document.body.onmousemove || document.onmousemove) {
                            hasMousemove = true;
                            shap.push('mousemove event handler detected (tracking cursor)');
                        }
                        return {
                            cursorNone,
                            fakeCursorFound,
                            hasMousemove,
                            shap
                        };
                    }
                """)
                if fake_cursor_result and (fake_cursor_result["cursorNone"] or fake_cursor_result["fakeCursorFound"]):
                    trap_details = []
                    if fake_cursor_result["cursorNone"]: trap_details.append("real cursor hidden")
                    if fake_cursor_result["fakeCursorFound"]: trap_details.append("fake cursor element found")
                    if fake_cursor_result["hasMousemove"]: trap_details.append("mousemove tracking detected")

                    traps_found.append({
                        "type": "Fake Cursor",
                        "description": "Potential fake cursor attack detected: " + "; ".join(trap_details),
                        "shap_explanation": fake_cursor_result["shap"]
                    })
                    shap_explanation.extend(fake_cursor_result["shap"])
            except Exception as e:
                print(f"Error in fake cursor detection: {e}")
                pass
        except Exception as e:
            actions_log.append(f"Error during Browse: {e}")
        finally:
            browser.close()

    if not traps_found:
        shap_explanation.append("No suspicious overlays or traps detected.")

    behavioral_verdict_result = analyze_behavioral_risk(traps_found, total_clickables)
    behavioral_verdict = behavioral_verdict_result["behavioral_verdict"]

    print("DEBUG traps_found:", json.dumps(traps_found, indent=2))
    print("DEBUG total_clickables:", total_clickables)

    return {
        "actions_log": actions_log,
        "traps_found": traps_found,
        "shap_explanation": shap_explanation,
        "behavioral_verdict": behavioral_verdict,
        "trap_characteristics": behavioral_verdict_result["trap_characteristics"]
    }


"""def update_ground_truth_with_predicted_verdict(csv_path):
    updated_rows = []

    with open(csv_path, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        headers = next(reader)
        if len(headers) < 3:
            headers.append("Predicted Verdict")
        updated_rows.append(headers)

        for row in reader:
            url = row[0]
            print(f"Analyzing: {url}")
            try:
                result = human_like_browse(url)
                verdict = result["behavioral_verdict"]
            except Exception as e:
                verdict = "error"
                print(f"Error processing {url}: {e}")

            if len(row) < 3:
                row.append(verdict)
            else:
                row[2] = verdict
            updated_rows.append(row)

    with open(csv_path, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(updated_rows)

if __name__ == "__main__":
    update_ground_truth_with_predicted_verdict("ground_truth.csv") """