/**
 * HAR.ZAP UI Tooltips - Applies tooltips from ui_texts.json to Streamlit controls
 * Uses control IDs defined in JSON to match DOM elements
 */

const UITooltips = {
    texts: null,

    async loadTexts(url = '/ui_texts.json') {
        try {
            const response = await fetch(url);
            this.texts = await response.json();
            return this.texts;
        } catch (e) {
            console.warn('UITooltips: Could not load texts', e);
            return {};
        }
    },

    findControl(id) {
        // Streamlit uses data-testid for element identification
        return document.querySelector(`[data-testid="${id}"]`) ||
               document.querySelector(`#${id}`) ||
               document.querySelector(`[key="${id}"]`);
    },

    createTooltip(element, text) {
        if (!text || !element) return;

        // Check if tooltip already exists
        if (element.dataset.tooltipApplied) return;

        element.dataset.tooltipApplied = 'true';
        element.title = text;

        // Add custom tooltip wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'harzap-tooltip-wrapper';
        wrapper.style.position = 'relative';
        wrapper.style.display = 'inline-block';
        wrapper.style.width = '100%';

        const tooltip = document.createElement('span');
        tooltip.className = 'harzap-tooltip';
        tooltip.textContent = '?';
        tooltip.dataset.tooltip = text;
        tooltip.style.cssText = `
            position: absolute;
            right: 4px;
            top: 50%;
            transform: translateY(-50%);
            background: #4a90d9;
            color: white;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            cursor: help;
            z-index: 100;
        `;

        element.parentNode.insertBefore(wrapper, element);
        wrapper.appendChild(element);
        wrapper.appendChild(tooltip);

        // Hover tooltip
        tooltip.addEventListener('mouseenter', (e) => {
            const tip = document.createElement('div');
            tip.className = 'harzap-tooltip-text';
            tip.textContent = text;
            tip.style.cssText = `
                position: fixed;
                background: #333;
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 13px;
                max-width: 300px;
                z-index: 10000;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            `;
            tip.style.left = (e.pageX + 10) + 'px';
            tip.style.top = (e.pageY - 30) + 'px';
            document.body.appendChild(tip);
            tooltip._tipElement = tip;
        });

        tooltip.addEventListener('mouseleave', () => {
            if (tooltip._tipElement) {
                tooltip._tipElement.remove();
                tooltip._tipElement = null;
            }
        });
    },

    applyTooltips() {
        if (!this.texts) return;

        // Iterate through all tabs and controls
        for (const [tabName, controls] of Object.entries(this.texts)) {
            if (tabName.startsWith('_')) continue; // Skip metadata

            for (const [ctrlName, config] of Object.entries(controls)) {
                if (config.id && config.help) {
                    const element = this.findControl(config.id);
                    if (element) {
                        this.createTooltip(element, config.help);
                    }
                }
            }
        }
    },

    async init(textsUrl) {
        await this.loadTexts(textsUrl);
        this.applyTooltips();

        // Re-apply on Streamlit reruns (MutationObserver)
        const observer = new MutationObserver(() => {
            setTimeout(() => this.applyTooltips(), 100);
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    },

    // Get text by path: UITooltips.get('upload_tab', 'har_uploader', 'help')
    get(tab, ctrl, field = 'label') {
        return this.texts?.[tab]?.[ctrl]?.[field] || '';
    },

    // Get ID for a control
    getId(tab, ctrl) {
        return this.texts?.[tab]?.[ctrl]?.id || '';
    }
};

// Auto-init when DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => UITooltips.init());
} else {
    UITooltips.init();
}

// Export for module usage
if (typeof module !== 'undefined') {
    module.exports = UITooltips;
}
