/**
 * Helper do tworzenia elementów DOM bez użycia innerHTML
 */
export function createEl(tag, classes = [], text = '', parent = null) {
    const el = document.createElement(tag);
    if (classes.length > 0) {
        el.classList.add(...classes);
    }
    if (text) {
        el.textContent = text;
    }
    if (parent) {
        parent.appendChild(el);
    }
    return el;
}

export function clearContainer(container) {
    while (container.firstChild) {
        container.removeChild(container.firstChild);
    }
}