/* SPDX-License-Identifier: GPL-3.0-or-later */
(function () {
    var global = this, haul = global.__haul_application;
    if (global.__webBrowserFullscreenInstalledV4) return true;
    if (!haul || typeof haul.l !== "function") return false;
    function patch(exports) {
        if (!exports) return;
        var normalize = exports.normalizeSelectedSize;
        if (typeof normalize === "function" && !normalize.__webBrowserFullscreenWrapped) {
            var replacement = function (preset, height, width) {
                if (__webBrowserFullscreenIsEnabled() && height && width)
                    return {preset: preset || null, height: height, width: width};
                return normalize.apply(this, arguments);
            };
            replacement.__webBrowserFullscreenWrapped = true;
            exports.normalizeSelectedSize = replacement;
            console.log("[fullscreen-jsc] selected-size helper wrapped");
        }
        var component = exports.default, prototype = component && component.prototype;
        if (!prototype || prototype.__webBrowserFullscreenWrapped ||
            typeof prototype.render !== "function" || typeof prototype.componentDidMount !== "function") return;
        var render = Function.prototype.toString.call(prototype.render);
        if (render.indexOf("WebBrowserActionCard") < 0 &&
            !(render.indexOf("WebViewPS") >= 0 && render.indexOf("cursorEnabled") >= 0 &&
              render.indexOf("onNavigationStateChange") >= 0 && render.indexOf("renderHeader") >= 0)) return;
        var mount = prototype.componentDidMount;
        prototype.componentDidMount = function () {
            var header = this.renderHeader;
            if (typeof header === "function" && !header.__webBrowserFullscreenWrapped) {
                this.renderHeader = function () {
                    return __webBrowserFullscreenIsEnabled() ? null : header.apply(this, arguments);
                };
                this.renderHeader.__webBrowserFullscreenWrapped = true;
            }
            if (__webBrowserFullscreenIsEnabled()) {
                this.state.hideHeader = true;
                this.resize({width: 1920, height: 1080});
            }
            return mount.apply(this, arguments);
        };
        prototype.__webBrowserFullscreenWrapped = true;
        console.log("[fullscreen-jsc] browser prototype wrapped");
    }
    /* Haul passes its cached exports and require function to each factory.
     * Module zero is a Babel helper already loaded by these applications. */
    haul.l(0, function (module, exports, require) {
        Object.keys(require.c).forEach(function (id) { patch(require.c[id].exports); });
    });
    var load = haul.l;
    haul.l = function (id, factory) {
        return load.call(this, id, function (module, exports, require) {
            var result = factory.call(this, module, exports, require);
            patch(module.exports);
            return result;
        });
    };
    Object.defineProperty(global, "__webBrowserFullscreenInstalledV4", {value: true});
    return true;
}).call(this);
