package com.protect7.authanalyzer.entities;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * Minimal {@link IHttpRequestResponse} holder used for requests that Auth
 * Analyzer sends itself over a direct connection (Kerberos sessions), outside of
 * {@code callbacks.makeHttpRequest}.
 *
 * @author Auth Analyzer
 */
public class SimpleHttpRequestResponse implements IHttpRequestResponse {

	private byte[] request;
	private byte[] response;
	private IHttpService httpService;
	private String comment;
	private String highlight;

	public SimpleHttpRequestResponse(IHttpService httpService, byte[] request, byte[] response) {
		this.httpService = httpService;
		this.request = request;
		this.response = response;
	}

	@Override
	public byte[] getRequest() {
		return request;
	}

	@Override
	public void setRequest(byte[] message) {
		this.request = message;
	}

	@Override
	public byte[] getResponse() {
		return response;
	}

	@Override
	public void setResponse(byte[] message) {
		this.response = message;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.httpService = httpService;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	@Override
	public String getHighlight() {
		return highlight;
	}

	@Override
	public void setHighlight(String color) {
		this.highlight = color;
	}
}
