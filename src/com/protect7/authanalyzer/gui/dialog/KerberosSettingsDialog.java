package com.protect7.authanalyzer.gui.dialog;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;

import com.protect7.authanalyzer.entities.KerberosConfig;
import com.protect7.authanalyzer.entities.KerberosConfig.CredentialSource;
import com.protect7.authanalyzer.gui.entity.SessionPanel;

/**
 * Dialog to configure the Kerberos / SPNEGO settings of a session.
 *
 * @author Auth Analyzer
 */
public class KerberosSettingsDialog extends JDialog {

	private static final long serialVersionUID = 1L;
	private final int TEXTFIELD_WIDTH = 32;

	private final KerberosConfig config;

	private final JRadioButton ccacheRadio = new JRadioButton("Ticket cache (ccache)");
	private final JRadioButton keytabRadio = new JRadioButton("Keytab");
	private final JTextField ccachePathField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField keytabPathField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField principalField = new JTextField(TEXTFIELD_WIDTH);

	private final JRadioButton deriveSpnRadio = new JRadioButton("Derive from target host");
	private final JRadioButton fixedSpnRadio = new JRadioButton("Fixed service principal name");
	private final JTextField serviceClassField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField spnField = new JTextField(TEXTFIELD_WIDTH);

	private final JCheckBox useSpnegoBox = new JCheckBox("Wrap token in SPNEGO (standard HTTP Negotiate)");
	private final JCheckBox mutualAuthBox = new JCheckBox("Request mutual authentication");
	private final JCheckBox credDelegBox = new JCheckBox("Request credential delegation");

	private final JTextField krb5ConfField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField realmField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField kdcField = new JTextField(TEXTFIELD_WIDTH);
	private final JTextField reloginField = new JTextField(TEXTFIELD_WIDTH);

	private final JButton okButton = new JButton("OK");
	private final JButton cancelButton = new JButton("Cancel");

	public KerberosSettingsDialog(SessionPanel sessionPanel) {
		this.config = sessionPanel.getKerberosConfig();

		JPanel contentPanel = (JPanel) getContentPane();
		contentPanel.setLayout(new GridBagLayout());
		contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		ButtonGroup credentialGroup = new ButtonGroup();
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
		c.gridwidth = 2;
		c.insets = new Insets(2, 2, 2, 2);

		addSectionLabel(contentPanel, c, "Credential source");
		c.gridwidth = 1;
		addRow(contentPanel, c, ccacheRadio, keytabRadio);
		addLabeledField(contentPanel, c, "Ticket cache path", ccachePathField,
				"Leave empty to use the default (e.g. KRB5CCNAME / /tmp/krb5cc_<uid>)");
		addLabeledField(contentPanel, c, "Keytab path", keytabPathField, null);
		addLabeledField(contentPanel, c, "Client principal", principalField,
				"e.g. lowpriv@EXAMPLE.COM (required for keytab, optional for ccache)");

		c.gridwidth = 2;
		addSectionLabel(contentPanel, c, "Service principal (target)");
		c.gridwidth = 1;
		addRow(contentPanel, c, deriveSpnRadio, fixedSpnRadio);
		addLabeledField(contentPanel, c, "Service class", serviceClassField,
				"Used with 'Derive from target host' -> <class>@<host>, e.g. HTTP");
		addLabeledField(contentPanel, c, "Fixed SPN", spnField,
				"Used with 'Fixed service principal name', e.g. HTTP/host.example.com@EXAMPLE.COM");

		c.gridwidth = 2;
		addSectionLabel(contentPanel, c, "Token options");
		addFullWidth(contentPanel, c, useSpnegoBox);
		addFullWidth(contentPanel, c, mutualAuthBox);
		addFullWidth(contentPanel, c, credDelegBox);

		addSectionLabel(contentPanel, c, "Kerberos environment (optional)");
		c.gridwidth = 1;
		addLabeledField(contentPanel, c, "krb5.conf path", krb5ConfField,
				"Leave empty to use the system / default krb5.conf");
		addLabeledField(contentPanel, c, "Default realm", realmField, null);
		addLabeledField(contentPanel, c, "KDC host", kdcField, null);
		addLabeledField(contentPanel, c, "Re-login interval (s)", reloginField,
				"Re-acquire the subject after this many seconds (0 = only on failure)");

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(okButton);
		buttonPanel.add(cancelButton);
		c.gridx = 0;
		c.gridy++;
		c.gridwidth = 2;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.CENTER;
		contentPanel.add(buttonPanel, c);

		loadFromConfig();
		updateEnabledState();

		ccacheRadio.addActionListener(e -> updateEnabledState());
		keytabRadio.addActionListener(e -> updateEnabledState());
		deriveSpnRadio.addActionListener(e -> updateEnabledState());
		fixedSpnRadio.addActionListener(e -> updateEnabledState());
		okButton.addActionListener(e -> {
			if (saveToConfig()) {
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
		JLabel label = new JLabel(text);
		label.setBorder(BorderFactory.createEmptyBorder(8, 0, 2, 0));
		c.gridx = 0;
		c.gridy++;
		panel.add(label, c);
	}

	private void addRow(JPanel panel, GridBagConstraints c, java.awt.Component left, java.awt.Component right) {
		c.gridx = 0;
		c.gridy++;
		panel.add(left, c);
		c.gridx = 1;
		panel.add(right, c);
	}

	private void addLabeledField(JPanel panel, GridBagConstraints c, String label, JTextField field, String hint) {
		c.gridx = 0;
		c.gridy++;
		panel.add(new JLabel(label), c);
		c.gridx = 1;
		panel.add(field, c);
		if (hint != null) {
			JLabel hintLabel = new JLabel("<html><i>" + hint + "</i></html>");
			hintLabel.putClientProperty("html.disable", null);
			hintLabel.setPreferredSize(new Dimension(360, hintLabel.getPreferredSize().height));
			c.gridx = 1;
			c.gridy++;
			panel.add(hintLabel, c);
		}
	}

	private void addFullWidth(JPanel panel, GridBagConstraints c, java.awt.Component component) {
		int previousWidth = c.gridwidth;
		c.gridwidth = 2;
		c.gridx = 0;
		c.gridy++;
		panel.add(component, c);
		c.gridwidth = previousWidth;
	}

	private void loadFromConfig() {
		if (config.getCredentialSource() == CredentialSource.KEYTAB) {
			keytabRadio.setSelected(true);
		} else {
			ccacheRadio.setSelected(true);
		}
		ccachePathField.setText(nullToEmpty(config.getCcachePath()));
		keytabPathField.setText(nullToEmpty(config.getKeytabPath()));
		principalField.setText(nullToEmpty(config.getPrincipal()));

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

		krb5ConfField.setText(nullToEmpty(config.getKrb5ConfPath()));
		realmField.setText(nullToEmpty(config.getRealm()));
		kdcField.setText(nullToEmpty(config.getKdc()));
		reloginField.setText(String.valueOf(config.getReloginIntervalSeconds()));
	}

	private boolean saveToConfig() {
		int reloginInterval;
		try {
			reloginInterval = Integer.parseInt(reloginField.getText().trim());
			if (reloginInterval < 0) {
				throw new NumberFormatException();
			}
		} catch (NumberFormatException e) {
			JOptionPane.showMessageDialog(this, "Re-login interval must be a non-negative integer (seconds).",
					"Validation Failed", JOptionPane.WARNING_MESSAGE);
			return false;
		}
		if (keytabRadio.isSelected() && principalField.getText().trim().isEmpty()) {
			JOptionPane.showMessageDialog(this, "A client principal is required when authenticating with a keytab.",
					"Validation Failed", JOptionPane.WARNING_MESSAGE);
			return false;
		}
		if (fixedSpnRadio.isSelected() && spnField.getText().trim().isEmpty()) {
			JOptionPane.showMessageDialog(this, "A fixed service principal name must be provided.",
					"Validation Failed", JOptionPane.WARNING_MESSAGE);
			return false;
		}

		config.setCredentialSource(keytabRadio.isSelected() ? CredentialSource.KEYTAB : CredentialSource.CCACHE);
		config.setCcachePath(ccachePathField.getText().trim());
		config.setKeytabPath(keytabPathField.getText().trim());
		config.setPrincipal(principalField.getText().trim());

		config.setDeriveSpnFromHost(deriveSpnRadio.isSelected());
		config.setServiceClass(serviceClassField.getText().trim());
		config.setServicePrincipalName(spnField.getText().trim());

		config.setUseSpnego(useSpnegoBox.isSelected());
		config.setRequestMutualAuth(mutualAuthBox.isSelected());
		config.setRequestCredDeleg(credDelegBox.isSelected());

		config.setKrb5ConfPath(krb5ConfField.getText().trim());
		config.setRealm(realmField.getText().trim());
		config.setKdc(kdcField.getText().trim());
		config.setReloginIntervalSeconds(reloginInterval);
		return true;
	}

	private void updateEnabledState() {
		ccachePathField.setEnabled(ccacheRadio.isSelected());
		keytabPathField.setEnabled(keytabRadio.isSelected());
		serviceClassField.setEnabled(deriveSpnRadio.isSelected());
		spnField.setEnabled(fixedSpnRadio.isSelected());
	}

	private static String nullToEmpty(String s) {
		return s == null ? "" : s;
	}
}
