package com.protect7.authanalyzer.gui.dialog;

import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;

import com.protect7.authanalyzer.entities.KerberosConfig;
import com.protect7.authanalyzer.entities.KerberosConfig.CredentialSource;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.util.KerberosTokenMinter;

/**
 * Dialog to configure the Kerberos / SPNEGO settings of a session, laid out in
 * the style of the "Kerberos Authentication" Burp extension.
 *
 * In Auth Analyzer every session is one Kerberos client (one identity). To test
 * several clients, create or clone a session per user and give each its own
 * credentials here.
 *
 * @author Auth Analyzer
 */
public class KerberosSettingsDialog extends JDialog {

	private static final long serialVersionUID = 1L;
	private final int TEXTFIELD_WIDTH = 30;
	private final int HINT_WIDTH = 440;

	private final KerberosConfig config;

	private final JRadioButton kerberosSchemeRadio = new JRadioButton("Kerberos (Negotiate)");
	private final JRadioButton ntlmSchemeRadio = new JRadioButton("NTLM");

	private final JRadioButton passwordRadio = new JRadioButton("Username / password");
	private final JRadioButton ccacheRadio = new JRadioButton("Ticket cache (ccache)");
	private final JRadioButton keytabRadio = new JRadioButton("Keytab");

	private final JTextField usernameField = new JTextField(TEXTFIELD_WIDTH);
	private final JPasswordField passwordField = new JPasswordField(TEXTFIELD_WIDTH);
	private final JCheckBox savePasswordBox = new JCheckBox("Save password in Burp config");
	private final JTextField domainField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField ccachePathField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField keytabPathField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField principalField = new JTextField(TEXTFIELD_WIDTH);
	private final JButton testCredentialsButton = new JButton("Test credentials");

	private final JTextField realmField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField kdcField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField krb5ConfField = new JTextField(TEXTFIELD_WIDTH);

	private final JRadioButton deriveSpnRadio = new JRadioButton("Derive from target host");
	private final JRadioButton fixedSpnRadio = new JRadioButton("Fixed service principal name");
	private final JTextField serviceClassField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField spnField = new JTextField(TEXTFIELD_WIDTH);

	private final JCheckBox useSpnegoBox = new JCheckBox("Wrap token in SPNEGO (standard HTTP Negotiate)");
	private final JCheckBox mutualAuthBox = new JCheckBox("Request mutual authentication");
	private final JCheckBox credDelegBox = new JCheckBox("Request credential delegation");
	private final JCheckBox directConnectionBox = new JCheckBox("Send over a fresh connection (bypass Burp pool / Platform Auth)");

	private final JTextField reloginField = new JTextField(TEXTFIELD_WIDTH);

	private final JButton okButton = new JButton("OK");
	private final JButton cancelButton = new JButton("Cancel");

	public KerberosSettingsDialog(SessionPanel sessionPanel) {
		this.config = sessionPanel.getKerberosConfig();

		JPanel contentPanel = (JPanel) getContentPane();
		contentPanel.setLayout(new GridBagLayout());
		contentPanel.setBorder(new EmptyBorder(10, 12, 10, 12));

		ButtonGroup schemeGroup = new ButtonGroup();
		schemeGroup.add(kerberosSchemeRadio);
		schemeGroup.add(ntlmSchemeRadio);

		ButtonGroup credentialGroup = new ButtonGroup();
		credentialGroup.add(passwordRadio);
		credentialGroup.add(ccacheRadio);
		credentialGroup.add(keytabRadio);

		ButtonGroup spnGroup = new ButtonGroup();
		spnGroup.add(deriveSpnRadio);
		spnGroup.add(fixedSpnRadio);

		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridwidth = 1;
		c.insets = new Insets(2, 2, 2, 8);

		addFullWidth(contentPanel, c, createHintLabel("Each session is one client. To test several clients, "
				+ "create or clone a session per user and set its own credentials here."));

		addSectionLabel(contentPanel, c, "Authentication scheme");
		addRow(contentPanel, c, kerberosSchemeRadio, ntlmSchemeRadio);
		addFullWidth(contentPanel, c, createHintLabel("NTLM uses a username/password handshake and is always sent over a fresh connection. "
				+ "The ticket cache, keytab, service principal, SPNEGO and domain/KDC options below apply to Kerberos only."));

		addSectionLabel(contentPanel, c, "Credential source");
		addFullWidth(contentPanel, c, passwordRadio);
		addLabeledField(contentPanel, c, "Username", usernameField, "e.g. lowpriv, DOMAIN\\lowpriv or lowpriv@EXAMPLE.COM");
		addLabeledField(contentPanel, c, "Password", passwordField, null);
		addLabeledField(contentPanel, c, "Domain (NTLM)", domainField,
				"NetBIOS or DNS domain for NTLM, e.g. EXAMPLE. Optional if the username is given as DOMAIN\\user.");
		addFullWidth(contentPanel, c, savePasswordBox);
		addFullWidth(contentPanel, c, createHintLabel("If unchecked the password is kept in memory only and is not written to the Burp project / config."));
		addFullWidth(contentPanel, c, ccacheRadio);
		addLabeledField(contentPanel, c, "Ticket cache path", ccachePathField,
				"Leave empty to use the default (e.g. KRB5CCNAME or /tmp/krb5cc_<uid>). Obtain a ticket beforehand with kinit.");
		addFullWidth(contentPanel, c, keytabRadio);
		addLabeledField(contentPanel, c, "Keytab path", keytabPathField, null);
		addLabeledField(contentPanel, c, "Client principal", principalField,
				"Required for keytab (e.g. lowpriv@EXAMPLE.COM). Optional for ccache / password.");
		addFullWidth(contentPanel, c, testCredentialsButton);

		addSectionLabel(contentPanel, c, "Domain settings");
		addLabeledField(contentPanel, c, "Domain / realm", realmField,
				"AD domain or Kerberos realm, e.g. EXAMPLE.COM (entering example.com is fine, it is upper-cased for the realm).");
		addLabeledField(contentPanel, c, "KDC host", kdcField, "Domain controller / KDC host, e.g. dc01.example.com");
		addLabeledField(contentPanel, c, "krb5.conf file", krb5ConfField,
				"Optional. When Domain/realm and KDC are set, a minimal krb5.conf is generated automatically. "
				+ "Provide a path only to use your own krb5.conf (it then overrides Domain/realm and KDC above).");

		addSectionLabel(contentPanel, c, "Service principal (target)");
		addFullWidth(contentPanel, c, deriveSpnRadio);
		addLabeledField(contentPanel, c, "Service class", serviceClassField,
				"Used with 'Derive from target host' -> <class>@<host>, e.g. HTTP");
		addFullWidth(contentPanel, c, fixedSpnRadio);
		addLabeledField(contentPanel, c, "Fixed SPN", spnField, "e.g. HTTP/host.example.com@EXAMPLE.COM");

		addSectionLabel(contentPanel, c, "Token options");
		addFullWidth(contentPanel, c, useSpnegoBox);
		addFullWidth(contentPanel, c, mutualAuthBox);
		addFullWidth(contentPanel, c, credDelegBox);
		addFullWidth(contentPanel, c, directConnectionBox);
		addFullWidth(contentPanel, c, createHintLabel("Keep this on for per-request / per-connection Negotiate (IIS, Windows Integrated Auth). "
				+ "It opens a dedicated connection with 'Connection: close' so the minted token is the identity the server sees, "
				+ "instead of reusing a pooled connection already authenticated by Burp Platform Authentication."));
		addLabeledField(contentPanel, c, "Re-login interval (s)", reloginField,
				"Re-acquire the subject after this many seconds (a fresh token is still minted per request). 0 = only on failure.");

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(okButton);
		buttonPanel.add(cancelButton);
		c.gridx = 0;
		c.gridy++;
		c.gridwidth = 2;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.CENTER;
		contentPanel.add(buttonPanel, c);

		// Filler so the whole form stays anchored to the top if the window is larger than needed.
		c.gridx = 0;
		c.gridy++;
		c.gridwidth = 2;
		c.weightx = 1;
		c.weighty = 1;
		c.fill = GridBagConstraints.BOTH;
		c.anchor = GridBagConstraints.NORTHWEST;
		contentPanel.add(Box.createGlue(), c);

		loadFromConfig();
		updateEnabledState();

		kerberosSchemeRadio.addActionListener(e -> updateEnabledState());
		ntlmSchemeRadio.addActionListener(e -> updateEnabledState());
		passwordRadio.addActionListener(e -> updateEnabledState());
		ccacheRadio.addActionListener(e -> updateEnabledState());
		keytabRadio.addActionListener(e -> updateEnabledState());
		deriveSpnRadio.addActionListener(e -> updateEnabledState());
		fixedSpnRadio.addActionListener(e -> updateEnabledState());
		testCredentialsButton.addActionListener(e -> testCredentials());
		okButton.addActionListener(e -> {
			if (collectInto(config, config.isEnabled())) {
				dispose();
			}
		});
		cancelButton.addActionListener(e -> dispose());

		setTitle("Kerberos Settings for Session " + sessionPanel.getSessionName());
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(sessionPanel);
		setModal(true);
		setVisible(true);
	}

	private void addSectionLabel(JPanel panel, GridBagConstraints c, String text) {
		JLabel label = new JLabel("<html><b>" + text + "</b></html>");
		label.putClientProperty("html.disable", null);
		label.setBorder(BorderFactory.createEmptyBorder(12, 0, 2, 0));
		c.gridwidth = 2;
		c.gridx = 0;
		c.gridy++;
		panel.add(label, c);
		c.gridwidth = 1;
	}

	private void addRow(JPanel panel, GridBagConstraints c, Component left, Component right) {
		c.gridwidth = 1;
		c.gridx = 0;
		c.gridy++;
		panel.add(left, c);
		c.gridx = 1;
		panel.add(right, c);
	}

	private void addLabeledField(JPanel panel, GridBagConstraints c, String label, Component field, String hint) {
		c.gridwidth = 1;
		c.gridx = 0;
		c.gridy++;
		panel.add(new JLabel(label), c);
		c.gridx = 1;
		panel.add(field, c);
		if (hint != null) {
			c.gridx = 1;
			c.gridy++;
			panel.add(createHintLabel(hint), c);
		}
	}

	private void addFullWidth(JPanel panel, GridBagConstraints c, Component component) {
		c.gridwidth = 2;
		c.gridx = 0;
		c.gridy++;
		panel.add(component, c);
		c.gridwidth = 1;
	}

	private JLabel createHintLabel(String hint) {
		// Fixed width div so the HTML label reports a correct multi-line height and does not overlap the next row.
		JLabel hintLabel = new JLabel("<html><div style='width:" + HINT_WIDTH + "px;'>" + hint + "</div></html>");
		hintLabel.putClientProperty("html.disable", null);
		hintLabel.setForeground(Color.GRAY);
		hintLabel.setFont(hintLabel.getFont().deriveFont(Font.ITALIC, hintLabel.getFont().getSize2D() - 1f));
		hintLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
		return hintLabel;
	}

	private void loadFromConfig() {
		if (config.getAuthScheme() == KerberosConfig.AuthScheme.NTLM) {
			ntlmSchemeRadio.setSelected(true);
		} else {
			kerberosSchemeRadio.setSelected(true);
		}
		domainField.setText(nullToEmpty(config.getDomain()));
		if (config.getCredentialSource() == CredentialSource.KEYTAB) {
			keytabRadio.setSelected(true);
		} else if (config.getCredentialSource() == CredentialSource.CCACHE) {
			ccacheRadio.setSelected(true);
		} else {
			passwordRadio.setSelected(true);
		}
		usernameField.setText(nullToEmpty(config.getUsername()));
		passwordField.setText(nullToEmpty(config.getPassword()));
		savePasswordBox.setSelected(config.isSavePassword());
		ccachePathField.setText(nullToEmpty(config.getCcachePath()));
		keytabPathField.setText(nullToEmpty(config.getKeytabPath()));
		principalField.setText(nullToEmpty(config.getPrincipal()));

		realmField.setText(nullToEmpty(config.getRealm()));
		kdcField.setText(nullToEmpty(config.getKdc()));
		krb5ConfField.setText(nullToEmpty(config.getKrb5ConfPath()));

		if (config.isDeriveSpnFromHost()) {
			deriveSpnRadio.setSelected(true);
		} else {
			fixedSpnRadio.setSelected(true);
		}
		serviceClassField.setText(config.getServiceClass());
		spnField.setText(nullToEmpty(config.getServicePrincipalName()));

		useSpnegoBox.setSelected(config.isUseSpnego());
		mutualAuthBox.setSelected(config.isRequestMutualAuth());
		credDelegBox.setSelected(config.isRequestCredDeleg());
		directConnectionBox.setSelected(config.isDirectConnection());
		reloginField.setText(String.valueOf(config.getReloginIntervalSeconds()));
	}

	/**
	 * Validates the form and writes it into the given config. Returns false (and
	 * shows a message) if validation fails.
	 */
	private boolean collectInto(KerberosConfig target, boolean enabled) {
		int reloginInterval;
		try {
			reloginInterval = Integer.parseInt(reloginField.getText().trim());
			if (reloginInterval < 0) {
				throw new NumberFormatException();
			}
		} catch (NumberFormatException e) {
			warn("Re-login interval must be a non-negative integer (seconds).");
			return false;
		}
		boolean ntlm = ntlmSchemeRadio.isSelected();
		if (ntlm && usernameField.getText().trim().isEmpty()) {
			warn("A username is required for NTLM authentication.");
			return false;
		}
		if (!ntlm && passwordRadio.isSelected() && usernameField.getText().trim().isEmpty()) {
			warn("A username is required for username / password authentication.");
			return false;
		}
		if (!ntlm && keytabRadio.isSelected() && principalField.getText().trim().isEmpty()) {
			warn("A client principal is required when authenticating with a keytab.");
			return false;
		}
		if (!ntlm && fixedSpnRadio.isSelected() && spnField.getText().trim().isEmpty()) {
			warn("A fixed service principal name must be provided.");
			return false;
		}

		target.setAuthScheme(ntlm ? KerberosConfig.AuthScheme.NTLM : KerberosConfig.AuthScheme.KERBEROS);
		target.setDomain(domainField.getText().trim());
		if (keytabRadio.isSelected()) {
			target.setCredentialSource(CredentialSource.KEYTAB);
		} else if (ccacheRadio.isSelected()) {
			target.setCredentialSource(CredentialSource.CCACHE);
		} else {
			target.setCredentialSource(CredentialSource.PASSWORD);
		}
		target.setEnabled(enabled);
		target.setUsername(usernameField.getText().trim());
		target.setPassword(new String(passwordField.getPassword()));
		target.setSavePassword(savePasswordBox.isSelected());
		target.setCcachePath(ccachePathField.getText().trim());
		target.setKeytabPath(keytabPathField.getText().trim());
		target.setPrincipal(principalField.getText().trim());

		target.setRealm(realmField.getText().trim());
		target.setKdc(kdcField.getText().trim());
		target.setKrb5ConfPath(krb5ConfField.getText().trim());

		target.setDeriveSpnFromHost(deriveSpnRadio.isSelected());
		target.setServiceClass(serviceClassField.getText().trim());
		target.setServicePrincipalName(spnField.getText().trim());

		target.setUseSpnego(useSpnegoBox.isSelected());
		target.setRequestMutualAuth(mutualAuthBox.isSelected());
		target.setRequestCredDeleg(credDelegBox.isSelected());
		target.setDirectConnection(directConnectionBox.isSelected());
		target.setReloginIntervalSeconds(reloginInterval);
		return true;
	}

	private void testCredentials() {
		KerberosConfig temp = new KerberosConfig();
		if (!collectInto(temp, true)) {
			return;
		}
		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		testCredentialsButton.setEnabled(false);
		try {
			KerberosTokenMinter minter = new KerberosTokenMinter(temp);
			String principal = minter.testLogin();
			JOptionPane.showMessageDialog(this, "Login succeeded.\nAcquired principal: " + principal,
					"Test credentials", JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this,
					"Login failed:\n" + rootMessage(e)
							+ "\n\nMake sure Burp runs on a full JDK (not the bundled JRE) and that the domain / KDC settings are correct.",
					"Test credentials", JOptionPane.ERROR_MESSAGE);
		} finally {
			testCredentialsButton.setEnabled(true);
			setCursor(Cursor.getDefaultCursor());
		}
	}

	private void updateEnabledState() {
		boolean ntlm = ntlmSchemeRadio.isSelected();
		if (ntlm) {
			// NTLM needs a cleartext password; Kerberos-only controls do not apply.
			passwordRadio.setSelected(true);
			directConnectionBox.setSelected(true);
		}
		// Credential source radios (Kerberos only).
		passwordRadio.setEnabled(!ntlm);
		ccacheRadio.setEnabled(!ntlm);
		keytabRadio.setEnabled(!ntlm);

		usernameField.setEnabled(ntlm || passwordRadio.isSelected());
		passwordField.setEnabled(ntlm || passwordRadio.isSelected());
		savePasswordBox.setEnabled(ntlm || passwordRadio.isSelected());
		domainField.setEnabled(ntlm);
		ccachePathField.setEnabled(!ntlm && ccacheRadio.isSelected());
		keytabPathField.setEnabled(!ntlm && keytabRadio.isSelected());
		principalField.setEnabled(!ntlm);

		// Kerberos-only sections.
		deriveSpnRadio.setEnabled(!ntlm);
		fixedSpnRadio.setEnabled(!ntlm);
		serviceClassField.setEnabled(!ntlm && deriveSpnRadio.isSelected());
		spnField.setEnabled(!ntlm && fixedSpnRadio.isSelected());
		useSpnegoBox.setEnabled(!ntlm);
		mutualAuthBox.setEnabled(!ntlm);
		credDelegBox.setEnabled(!ntlm);
		realmField.setEnabled(!ntlm);
		kdcField.setEnabled(!ntlm);
		krb5ConfField.setEnabled(!ntlm);
		reloginField.setEnabled(!ntlm);
		directConnectionBox.setEnabled(!ntlm);
		// NTLM is validated by running against the target, not by a standalone login.
		testCredentialsButton.setEnabled(!ntlm);
	}

	private void warn(String message) {
		JOptionPane.showMessageDialog(this, message, "Validation Failed", JOptionPane.WARNING_MESSAGE);
	}

	private static String rootMessage(Throwable t) {
		Throwable cause = t;
		while (cause.getCause() != null && cause.getCause() != cause) {
			cause = cause.getCause();
		}
		String message = cause.getMessage();
		return message == null ? cause.getClass().getName() : (cause.getClass().getSimpleName() + ": " + message);
	}

	private static String nullToEmpty(String s) {
		return s == null ? "" : s;
	}
}
