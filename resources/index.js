document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
        const command = button.parentElement.querySelector("pre");
        if (!command) {
            return;
        }

        await copyText(command.innerText);
        button.innerText = "copied";
    });
});

async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return;
    } catch (_error) {
        const input = document.createElement("textarea");
        input.value = text;
        input.setAttribute("readonly", "");
        input.style.position = "absolute";
        input.style.left = "-9999px";
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        input.remove();
    }
}
