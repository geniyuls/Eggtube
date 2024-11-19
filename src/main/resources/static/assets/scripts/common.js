HTMLElement.prototype.hide = function () {
    this.classList.remove('-visible');
    return this;
}

HTMLElement.prototype.show = function () {
    this.classList.add('-visible');
    return this;
}
/**
 * @param {string} dataId
 * @returns {HTMLLabelElement}
 */
HTMLFormElement.prototype.findLabel = function (dataId) {
    return this.querySelector(`label.--obj-label[data-id="${dataId}"]`);
}

/**
 * @param {boolean}b
 * @param {string|undefined} warningText
 * @returns {HTMLLabelElement}
 */

HTMLLabelElement.prototype.setValid = function (b, warningText = undefined) {
    if (b === true) {
        this.classList.remove('-invalid');
    } else if (b === false) {
        this.classList.add('-invalid');
        if (typeof warningText === 'string') {
            this.querySelector(`:scope > ._warning`).innerText = warningText;
        }
    }
    return this;
}

HTMLLabelElement.prototype.isValid = function () {
    return !this.classList.contains('-invalid');
}

class Dialog {
    /** @type {HTMLElement} */
    static $cover;
    /** @type {Array<HTMLElement>} */
    static $dialogArray = [];

    /**
     * @param {HTMLElement} $dialog
     */
    static hide($dialog) {
        Dialog.$dialogArray.splice(Dialog.$dialogArray.indexOf($dialog), 1);
        if (Dialog.$dialogArray.length === 0) {
            Dialog.$cover.hide();
        }
            $dialog.hide();
            setTimeout(() => $dialog.remove(), 1000);
    };

    /**
     * @param {Object} args
     * @param {string} args.title
     * @param {string} args.content
     * @param {Array<{string, onclick: function}>|undefined} args.buttons
     * @param {number} delay
     * @return {HTMLElement}
     */
    static show(args, delay = 50) {
        const $dialog = document.createElement('div');
        $dialog.classList.add('---dialog');
        const $title = document.createElement('div');
        $title.classList.add('_title');
        $title.innerText = args.title;
        const $content = document.createElement('div');
        $content.classList.add('_content');
        $content.innerText = args.content;
        $dialog.append($title, $content);
        if (args.buttons != null && args.buttons.length > 0) {
            const $buttonContainer = document.createElement('div');
            $buttonContainer.classList.add('_button-container');
            $buttonContainer.style.gridTemplateColumns = `repeat(${args.buttons.length}, 1fr)`;
            for (const button of args.buttons) {
                const $button = document.createElement('button');
                $button.classList.add('_button');
                $button.setAttribute('type', 'button');
                $button.innerText = button.text;
                if (typeof button.onclick === 'function') {
                    $button.onclick = () => button.onclick($dialog); // 버튼 클릭시, 현재 생성하고 있는 다이얼로그 요소를 인자로 전달해줌
                }
                $buttonContainer.append($button)
            }
            $dialog.append($buttonContainer);
        }
        document.body.prepend($dialog); // append는 제일 끝(마지막 자식)에, prepend는 제일 앞(첫번쨰 자식)에 추가
        Dialog.$dialogArray.push($dialog); // 다이얼로그 배열에 현재 생성된 다이얼로그 추가
        if (Dialog.$cover == null) {
            const $cover = document.createElement('div');
            $cover.classList.add('---dialog-cover');
            document.body.prepend($cover);
            Dialog.$cover = $cover;
        }
        setTimeout(() => {
            $dialog.show();
            Dialog.$cover.show();
        }, delay); //delay 밀리초 뒤에 show 해주는 이유는, 요소 생성 직후 -visible 붙이면, 트렌지션이 안먹히기 떄문
        return $dialog;
    }
}

class Loading{
    /** @type {HTMLElement} */
    static $element;
    static hide(){
        Loading.$element?.hide();
    }

    /**
     * @param{number} delay
     */
    static show(delay= 50){
        if (Loading.$element == null){
            const $element = document.createElement('div');
            $element.classList.add('---loading');
            const $icon = document.createElement('img');
            $icon.classList.add('_icon');
            $icon.setAttribute('alt', '');
            $icon.setAttribute('src', 'data:image/png;base64,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');
            const $text =document.createElement('span');
            $text.classList.add('_text');
            $text.innerText = '잠시만 기다려주세요.';
            $element.append($icon, $text);
            document.body.prepend($element);
            Loading.$element = $element;
        }
        setTimeout(() => Loading.$element.show(), delay);
    }
}