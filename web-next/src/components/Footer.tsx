import { useI18n } from "../i18n/context";
import "./Footer.css";

export function Footer() {
  const { t } = useI18n();
  return (
    <footer className="footer">
      <div className="wrap footer-wrap">
        <div className="footer-left">
          <div className="footer-brand display">NeoShell</div>
          <div className="footer-meta mono">{t("footer.meta")}</div>
        </div>
        <div className="footer-right">
          <div className="footer-version">
            <span className="footer-version-label mono">{t("footer.version")}</span>
            <span className="footer-version-value display">v0.6.26</span>
          </div>
          <div className="footer-links">
            <a href="https://github.com/uk0/NeoShell" target="_blank" rel="noopener" className="u-link">GitHub</a>
            <a href="https://firsh.me" target="_blank" rel="noopener" className="u-link">firsh.me</a>
            <a href="https://neoshell.wwwneo.com/updates/update.json" target="_blank" rel="noopener" className="u-link mono">update.json</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
