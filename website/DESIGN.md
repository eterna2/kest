```markdown
# Design System Document: The Obsidian Lens

## 1. Overview & Creative North Star
**Creative North Star: "The Digital Observatory"**

The objective of this design system is to move beyond the utilitarian nature of standard documentation and into the realm of high-end editorial precision. We are building a portal that feels less like a "help desk" and more like a premium technical journal. 

To achieve this, we reject the "boxy" nature of traditional web layouts. We embrace **intentional asymmetry**, where content floats within a vast, deep-space environment. The experience is defined by high-contrast typography, breathtaking breathing room, and a physical sense of depth created through light-bending glass rather than rigid lines. This is a "Technical Apple" aesthetic: hyper-clean, authoritative, and impossibly smooth.

---

### 2. Colors & Surface Philosophy

The palette is rooted in the depth of `surface` (#0c1324), providing a canvas that feels infinite rather than constrained.

#### The "No-Line" Rule
Standard 1px borders are strictly prohibited for sectioning. Structural definition must be achieved through **Tonal Shifting**. 
- **Example:** A navigation sidebar does not have a border; it is a `surface-container-low` layer sitting over the `surface` background, or it is a glass element defined by its blur.

#### Surface Hierarchy & Nesting
Treat the UI as an architectural stack.
*   **Level 0 (Foundation):** `surface` (#0c1324) - The base layer.
*   **Level 1 (Submerged):** `surface-container-lowest` (#070d1f) - Use for inset code blocks or "wells" within a page.
*   **Level 2 (Elevated):** `surface-container-high` (#23293c) - Use for floating cards or interactive modules.

#### The "Glass & Gradient" Rule
To capture the premium "Kest" identity:
*   **Glassmorphism:** Use `surface-container` at 60% opacity with a `backdrop-filter: blur(20px)`. This is mandatory for sidebars and top navigation to allow the `primary` accents of the content to bleed through as the user scrolls.
*   **Signature Textures:** Main CTAs and Hero headers should utilize a subtle linear gradient: `primary-container` (#4f46e5) to `primary` (#c3c0ff) at a 135-degree angle. This adds a "lithic" weight that flat hex codes cannot replicate.

---

### 3. Typography: Editorial Authority

We use a dual-typeface system to balance technical clarity with high-end brand appeal.

*   **Display & Headlines (Manrope):** This is our "Brand Voice." Use `display-lg` through `headline-sm` for page titles and major section starts. The geometric nature of Manrope should be tracked tightly (-0.02em) to feel premium and "engineered."
*   **Body & Utility (Inter):** This is our "Functional Voice." Inter provides maximum legibility for long-form documentation. Use `body-md` for standard text and `label-sm` for technical metadata.

**The Hierarchy Rule:** Always pair a `display-md` headline with a `label-md` uppercase sub-header (using `primary` color) to create a sophisticated, "magazine-style" entry point for every article.

---

### 4. Elevation & Depth

#### The Layering Principle
Instead of shadows, we communicate "lift" through color. A `surface-container-highest` object sitting on a `surface` background creates a natural optical lift.

#### Ambient Shadows
When an element must float (e.g., a Modal or a Hovering Tooltip), use a "Deep Space Shadow":
*   **Value:** `0px 24px 48px rgba(0, 0, 0, 0.4)`
*   **Tinting:** Inject 4% of the `on-surface` (#dce1fb) color into the shadow to prevent it from looking like a "dead" black hole. It should look like light is being absorbed.

#### The "Ghost Border" Fallback
If a visual separator is unavoidable for accessibility:
*   Use `outline-variant` (#464555) at **15% opacity**. 
*   Never use 100% opacity borders; they "trap" the content and ruin the minimalist flow.

---

### 5. Components

#### Buttons
*   **Primary:** A gradient-fill (from `primary-container` to `primary`) with `on-primary` text. No border. Large horizontal padding (24px) to emphasize the "Apple-esque" footprint.
*   **Secondary:** `surface-container-highest` background with a `Ghost Border`.
*   **Tertiary:** Pure text in `primary` with an underline that only appears on hover.

#### Chips (Tagging)
*   Use `surface-container-high` with `label-sm` text. 
*   **Radius:** Always `full` (9999px) to contrast against the more geometric `xl` (0.75rem) radius of cards.

#### Input Fields
*   **Background:** `surface-container-low`.
*   **Interaction:** On focus, the background remains static, but the `Ghost Border` transitions to 40% opacity `primary`. This subtle glow signals "active" without jarring the user.

#### Code Blocks (The "Technical" Core)
*   Background: `surface-container-lowest`. 
*   The code block should have no border but a "Glass" header bar (using `surface-container` at 50% opacity) containing the language label and "Copy" action.

#### Sidebars
*   Must utilize the **Glassmorphism Rule**. 
*   Active states in the sidebar should not be boxes; they should be a vertical 2px pill of `primary` color 4px to the left of the text.

---

### 6. Do’s and Don’ts

**Do:**
*   **Do** use extreme white space. If you think there is enough margin between sections, double it.
*   **Do** use `primary` (#c3c0ff) sparingly as a "highlighter." It is a surgical tool, not a paint bucket.
*   **Do** ensure all icons are "Light" or "Thin" weight to match the `Inter` typography.

**Don’t:**
*   **Don’t** use dividers (`<hr>`). Use a 64px or 80px gap from the Spacing Scale instead.
*   **Don’t** use pure #000000. It kills the depth. Stick to `surface` (#0c1324).
*   **Don’t** use standard "Blue" links. Use `primary` or `tertiary` tokens for all interactive text.
*   **Don't** use sharp 90-degree corners. Even for "technical" styles, the `sm` (0.125rem) radius provides a necessary "softness" to the digital edge.

---

### 7. Signature Interaction: The "Kest" Glow
When a user hovers over a primary card or navigation item, apply a subtle radial gradient background that follows the cursor at 5% opacity. This "spotlight" effect reinforces the "Digital Observatory" theme—that the user is illuminating the documentation as they explore it.```