import { test, expect } from "@playwright/test";

test.describe("CipherMesh End-to-End Multi-Browser Verification", () => {
  test("Two independent browser contexts register, establish an encrypted conversation, exchange encrypted messages, and verify contact safety numbers", async ({
    browser,
  }) => {
    const suffix = Date.now().toString().slice(-6);
    const aliceUsername = `alice_e2e_${suffix}`;
    const bobUsername = `bob_e2e_${suffix}`;

    const aliceContext = await browser.newContext();
    const bobContext = await browser.newContext();

    const alicePage = await aliceContext.newPage();
    const bobPage = await bobContext.newPage();

    await alicePage.setViewportSize({ width: 1440, height: 900 });
    await bobPage.setViewportSize({ width: 1440, height: 900 });

    // 1. Verify Landing Page on Alice's browser
    await alicePage.goto("/");
    await expect(
      alicePage.getByRole("heading", {
        name: /Your conversations\. Your keys\. Your privacy\./i,
      })
    ).toBeVisible();
    await alicePage.screenshot({
      path: "public/screenshots/landing-page.png",
      fullPage: false,
    });

    // 2. Register Alice
    await alicePage.goto("/register");
    await alicePage.locator("#reg-username").fill(aliceUsername);
    await alicePage.locator("#reg-display-name").fill("Alice E2E Node");
    await alicePage
      .locator("#reg-email")
      .fill(`${aliceUsername}@ciphermesh.sec`);
    await alicePage.locator("#reg-password").fill("CipherMesh_E2E_2026!");
    await alicePage
      .locator("#reg-device-label")
      .fill("Alice Chromium Workstation");
    await alicePage
      .getByRole("button", { name: /Generate Keys & Create Identity/i })
      .click();

    await alicePage.waitForURL("**/app", { timeout: 25000 });
    await expect(alicePage.getByText(`@${aliceUsername}`)).toBeVisible();

    // 3. Register Bob in independent browser context
    await bobPage.goto("/register");
    await bobPage.locator("#reg-username").fill(bobUsername);
    await bobPage.locator("#reg-display-name").fill("Bob E2E Node");
    await bobPage.locator("#reg-email").fill(`${bobUsername}@ciphermesh.sec`);
    await bobPage.locator("#reg-password").fill("CipherMesh_E2E_2026!");
    await bobPage.locator("#reg-device-label").fill("Bob Chromium Workstation");
    await bobPage
      .getByRole("button", { name: /Generate Keys & Create Identity/i })
      .click();

    await bobPage.waitForURL("**/app", { timeout: 25000 });
    await expect(bobPage.getByText(`@${bobUsername}`)).toBeVisible();

    // 4. Alice initiates a new encrypted conversation with Bob
    await alicePage
      .getByRole("button", { name: /Start new encrypted conversation/i })
      .click();
    await alicePage
      .getByPlaceholder("Search peer username or display name...")
      .fill(bobUsername);
    await alicePage.getByText("Bob E2E Node").click();

    // 5. Alice sends an E2EE message to Bob
    const testSecretMessage = `E2EE_VERIFIED_PACKET_${suffix}`;
    await alicePage
      .getByLabel("Encrypted message input")
      .fill(testSecretMessage);
    await alicePage
      .getByRole("button", { name: /Encrypt and send message/i })
      .click();

    // Verify Alice sees her decrypted outgoing message
    await expect(alicePage.getByText(testSecretMessage)).toBeVisible({
      timeout: 15000,
    });

    // 6. Bob selects the conversation with Alice and decrypts the message
    await bobPage
      .getByRole("button", { name: /Start new encrypted conversation/i })
      .click();
    await bobPage
      .getByPlaceholder("Search peer username or display name...")
      .fill(aliceUsername);
    await bobPage.getByText("Alice E2E Node").click();

    await expect(bobPage.getByText(testSecretMessage)).toBeVisible({
      timeout: 15000,
    });

    // 7. Alice marks Bob's identity as verified in the Contact Security Inspector
    await alicePage
      .getByRole("button", { name: /Mark Contact Identity as Verified/i })
      .click();
    await expect(
      alicePage.getByText(/Verified Cryptographic Identity/i)
    ).toBeVisible();
    await alicePage.screenshot({
      path: "public/screenshots/encrypted-chat.png",
      fullPage: false,
    });

    // 8. Alice opens the Security Center and inspects actual session information
    await alicePage
      .getByRole("button", { name: "Security", exact: true })
      .click();
    await expect(
      alicePage.getByRole("heading", { name: /CipherMesh Security Center/i })
    ).toBeVisible();
    await expect(
      alicePage.getByText(/X25519-HKDF-SHA256-XChaCha20-Poly1305-Ed25519/i).first()
    ).toBeVisible();
    await alicePage.screenshot({
      path: "public/screenshots/security-center.png",
      fullPage: false,
    });

    // 9. Alice returns to Chats and sends an encrypted file attachment to Bob
    await alicePage
      .getByRole("button", { name: "Chats", exact: true })
      .click();

    const fileInput = alicePage.locator('input[type="file"]');
    await fileInput.setInputFiles({
      name: "classified-audit-report.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(
        "CipherMesh Encrypted File Payload Verification — SHA-256 Checked"
      ),
    });

    await expect(
      alicePage.getByText("classified-audit-report.txt").first()
    ).toBeVisible({ timeout: 15000 });
    await expect(
      bobPage.getByText("classified-audit-report.txt").first()
    ).toBeVisible({ timeout: 15000 });

    // 10. Alice enables 30s disappearing message TTL and verifies ephemeral banner
    await alicePage.getByRole("button", { name: "30s", exact: true }).click();
    await expect(
      alicePage.getByText(/Disappearing messages enabled \(30s expiry\)/i)
    ).toBeVisible();

    await aliceContext.close();
    await bobContext.close();
  });
});
