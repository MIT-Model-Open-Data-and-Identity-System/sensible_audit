from django.conf.urls import patterns, include, url

urlpatterns = patterns('',
	url(r'^accesses/?$', 'sensible_audit.audit.accesses'),
	url(r'^dashboard/?$', 'sensible_audit.audit.visualization'),
)
