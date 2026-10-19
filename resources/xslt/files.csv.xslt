<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:da="http://dataaccessioner.org/schema/dda-1-1"
                xmlns:premis="info:lc/xmlns/premis-v2" version="1.0">
  <xsl:output method="text" encoding="UTF-8" omit-xml-declaration="yes"/>
  <xsl:strip-space elements="*"/>
  <xsl:variable name="eol" select="'&#10;'"/>
  <xsl:template match="/">
    <xsl:text>"directory path","file name","file extension","last modified","size (bytes)","sha256","md5","file format","format version","format registry key/PUID","Identified By","MIME Type","ID Warning"</xsl:text>
    <xsl:value-of select="$eol"/>
    <xsl:for-each select="//da:file">
      <!-- directory path -->
      <xsl:text>"</xsl:text>
      <xsl:for-each select="ancestor::da:folder">
        <xsl:value-of select="@name"/>
        <xsl:text>/</xsl:text>
      </xsl:for-each>
      <xsl:text>",</xsl:text>

      <!-- file name -->
      <xsl:text>"</xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:text>",</xsl:text>

      <!-- file extension -->
      <xsl:text>"</xsl:text>
      <xsl:variable name="extension">
        <xsl:call-template name="get-file-extension">
          <xsl:with-param name="path" select="@name" />
        </xsl:call-template>
      </xsl:variable>
      <xsl:value-of select="$extension"/>
      <xsl:text>",</xsl:text>

      <!-- last modified -->
      <xsl:text>"</xsl:text>
      <xsl:value-of select="@last_modified"/>
      <xsl:text>",</xsl:text>

      <!-- size (bytes) -->
      <xsl:text>"</xsl:text>
      <xsl:value-of select="@size"/>
      <xsl:text>",</xsl:text>

      <!-- SHA-256 and explicitly labelled historical MD5 -->
      <xsl:text>"</xsl:text>
      <xsl:value-of select="@SHA256"/>
      <xsl:text>",</xsl:text>
      <xsl:text>"</xsl:text>
      <xsl:value-of select="@MD5"/>
      <xsl:text>",</xsl:text>

      <!-- file format -->
      <xsl:text>"</xsl:text>
      <xsl:call-template name="metadata-values"><xsl:with-param name="nodes" select="premis:object/premis:objectCharacteristics/premis:format/premis:formatDesignation/premis:formatName"/></xsl:call-template>
      <xsl:text>",</xsl:text>

      <!-- format version -->
      <xsl:text>"</xsl:text>
      <xsl:call-template name="metadata-values"><xsl:with-param name="nodes" select="premis:object/premis:objectCharacteristics/premis:format/premis:formatDesignation/premis:formatVersion"/></xsl:call-template>
      <xsl:text>",</xsl:text>

      <!-- format registry key/PUID -->
      <xsl:text>"</xsl:text>
      <xsl:call-template name="metadata-values"><xsl:with-param name="nodes" select="premis:object/premis:objectCharacteristics/premis:format/premis:formatRegistry/premis:formatRegistryKey"/></xsl:call-template>
      <xsl:text>",</xsl:text>

      <!-- Identified by -->
      <xsl:text>"</xsl:text>
      <xsl:call-template name="metadata-values"><xsl:with-param name="nodes" select="premis:object/premis:objectCharacteristics/premis:format/premis:formatNote[starts-with(text(), 'Identified by:')]"/><xsl:with-param name="start" select="16"/></xsl:call-template>
      <xsl:text>",</xsl:text>

      <!-- MIME Type -->
      <xsl:text>"</xsl:text>
      <xsl:call-template name="metadata-values"><xsl:with-param name="nodes" select="premis:object/premis:objectCharacteristics/premis:format/premis:formatNote[1]"/></xsl:call-template>
      <xsl:text>",</xsl:text>

      <!-- ID Warning -->
      <xsl:text>"</xsl:text>
      <xsl:for-each select="premis:object/premis:objectCharacteristics/premis:format/premis:formatNote[contains(., 'Identification Warning')]">
        <xsl:value-of select="."/>
        <xsl:if test="not(position() = last())">
          <xsl:text>|</xsl:text>
        </xsl:if>
      </xsl:for-each>
      <xsl:text>"</xsl:text>

      <xsl:value-of select="$eol"/>
    </xsl:for-each>
    <xsl:value-of select="$eol"/>
  </xsl:template>

  <!-- Get file extension -->
  <!-- Preserve all reported identities/tools and escape quotes in CSV fields. -->
  <xsl:template name="metadata-values">
    <xsl:param name="nodes"/>
    <xsl:param name="start" select="1"/>
    <xsl:for-each select="$nodes">
      <xsl:if test="position() != 1"><xsl:text> | </xsl:text></xsl:if>
      <xsl:call-template name="csv-escape">
        <xsl:with-param name="value" select="substring(., $start)"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>
  <xsl:template name="csv-escape">
    <xsl:param name="value"/>
    <xsl:choose>
      <xsl:when test="contains($value, '&quot;')">
        <xsl:value-of select="substring-before($value, '&quot;')"/>
        <xsl:text>""</xsl:text>
        <xsl:call-template name="csv-escape"><xsl:with-param name="value" select="substring-after($value, '&quot;')"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="$value"/></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="get-file-extension">
    <xsl:param name="path"/>
    <xsl:choose>
        <xsl:when test="contains($path, '/')">
            <xsl:call-template name="get-file-extension">
                <xsl:with-param name="path" select="substring-after($path, '/')"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="contains($path, '.')">
            <xsl:call-template name="getlastdot">
                <xsl:with-param name="tempstr" select="substring-after($path, '.')"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
            <xsl:text/>
        </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
  <xsl:template name="getlastdot">
    <xsl:param name="tempstr" />
    <xsl:choose>
      <xsl:when test="contains($tempstr, '.')">
        <xsl:call-template name="getlastdot">
          <xsl:with-param name="tempstr" select="substring-after($tempstr, '.')" />
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$tempstr" />
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
