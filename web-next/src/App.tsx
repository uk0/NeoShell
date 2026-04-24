import { Nav } from "./components/Nav";
import { Hero } from "./components/Hero";
import { Features } from "./components/Features";
import { Stack } from "./components/Stack";
import { Security } from "./components/Security";
import { Download } from "./components/Download";
import { Changelog } from "./components/Changelog";
import { Contact } from "./components/Contact";
import { Footer } from "./components/Footer";
import { Cursor } from "./components/Cursor";

export function App() {
  return (
    <>
      <Cursor />
      <Nav />
      <main>
        <Hero />
        <Features />
        <Stack />
        <Security />
        <Download />
        <Changelog />
        <Contact />
      </main>
      <Footer />
    </>
  );
}
