# Human-readable size conversion utilities

# Convert bytes to human-readable format (GB, MB, KB)
# Usage: format_bytes_human_readable(<bytes> <output_var>)
function(format_bytes_human_readable bytes output_var)
    math(EXPR size_gb "${bytes} / 1073741824")
    math(EXPR size_mb "${bytes} / 1048576")
    math(EXPR size_kb "${bytes} / 1024")

    if(size_gb GREATER 0)
        set(${output_var} "${size_gb} GB" PARENT_SCOPE)
    elseif(size_mb GREATER 0)
        set(${output_var} "${size_mb} MB" PARENT_SCOPE)
    else()
        set(${output_var} "${size_kb} KB" PARENT_SCOPE)
    endif()
endfunction()
